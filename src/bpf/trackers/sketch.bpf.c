/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Count-Min Sketch wakeup tracker -- the thing this whole study is about.
 *
 * A fixed table of width x depth counters. Each of the depth rows hashes an
 * identity to one of width columns with its own seed; incrementing bumps one
 * cell per row, and an estimate is the smallest of those cells. The estimate
 * can overshoot when unrelated identities collide, but by the standard
 * Count-Min guarantee (Cormode & Muthukrishnan, 2005) it never undershoots.
 * The point is that its memory is fixed by width and depth alone, and does
 * not grow with the number of distinct tasks -- which is exactly what the
 * exact counter cannot promise under process churn.
 *
 * Windowing matches the exact tracker: two buffers, an estimate sums both,
 * and the older is discarded at each rotation. Unlike the exact tracker the
 * discard is a real zeroing pass, not a lazy per-entry roll -- there is
 * nowhere to hang a per-entry epoch without adding a field to every cell,
 * which would inflate the very footprint being measured.
 *
 * Each buffer carries its own seeds. That is what makes seed rotation
 * (--seed-rotation) coherent: a fresh buffer can be given fresh seeds while
 * the surviving buffer is still read with the seeds it was written under.
 * The Python prototype does the same thing, indexing each buffer separately
 * rather than assuming a shared hash.
 *
 * Adaptation from Python worth stating: the prototype hashed identity
 * *strings*; here an identity is already a u64 (a pid, tgid, or hashed
 * comm), so the same FNV-1a construction runs over its eight bytes. The
 * seed-mixing and table structure are unchanged, so the collision behaviour
 * under a knowledgeable adversary -- the thing Section 4.1.1 found to be
 * structural rather than hash-specific -- is preserved.
 */

const volatile u32 cms_sketch_width = CMS_DFL_SKETCH_WIDTH;
const volatile u32 cms_sketch_depth = CMS_DFL_SKETCH_DEPTH;
const volatile bool cms_seed_rotation;

/*
 * The counter table, sized at load time to exactly 2 * width * depth cells.
 * Deliberately not a fixed-size array: an over-allocated table would make
 * the sketch's measured memory disagree with the memory it claims to use,
 * and that number is the whole point of the comparison.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);		/* resized by userspace before load */
	__type(key, u32);
	__type(value, u32);
} cms_sketch SEC(".maps");

/* Per-buffer, per-row hash seeds. Readable from userspace, which the
 * targeted-collision replication needs in order to play the adversary. */
u32 cms_sketch_seeds[2][CMS_SKETCH_MAX_DEPTH];

/* Which buffer inserts currently land in; the other holds last window. */
u32 cms_sketch_cur;

u64 cms_sketch_rotations;

/*
 * FNV-1a over the eight bytes of the identity, seed mixed into the basis.
 * Cheap enough for a per-wakeup hot path, which blake2b (used in the Python
 * prototype for reproducibility) would not be. Phase 1 established this
 * choice costs nothing in collision resistance, because both hashes proved
 * equally vulnerable to a targeted attack (paper Section 4.1.3).
 */
static __always_inline u32 cms_sketch_col(u64 id, u32 seed)
{
	u32 h = 0x811c9dc5U ^ seed;
	int i;

#pragma unroll
	for (i = 0; i < 8; i++) {
		h ^= (u32)((id >> (i * 8)) & 0xff);
		h *= 0x01000193U;
	}

	return h % cms_sketch_width;
}

static __always_inline u32 cms_sketch_idx(u32 buf, u32 row, u32 col)
{
	return (buf * cms_sketch_depth + row) * cms_sketch_width + col;
}

static __always_inline u32 *cms_sketch_cell(u32 buf, u32 row, u32 col)
{
	u32 idx = cms_sketch_idx(buf, row, col);

	return bpf_map_lookup_elem(&cms_sketch, &idx);
}

static __always_inline void cms_sketch_increment(u64 id)
{
	u32 buf = cms_sketch_cur & 1;
	u32 row;

	bpf_for(row, 0, cms_sketch_depth) {
		u32 *cell;

		if (row >= CMS_SKETCH_MAX_DEPTH)
			break;

		cell = cms_sketch_cell(buf, row,
				       cms_sketch_col(id, cms_sketch_seeds[buf][row]));
		if (cell)
			(*cell)++;
	}
}

/*
 * The Count-Min estimate: per row, this window's cell plus last window's,
 * then the minimum across rows. Summing the two buffers cell-wise before
 * taking the minimum is the mathematically correct merge -- it is equivalent
 * to having inserted both windows' events into a single sketch.
 */
static __always_inline u64 cms_sketch_query(u64 id)
{
	u32 cur = cms_sketch_cur & 1;
	u32 prev = cur ^ 1;
	u64 best = (u64)-1;
	u32 row;

	bpf_for(row, 0, cms_sketch_depth) {
		u32 *c, *p;
		u64 sum = 0;

		if (row >= CMS_SKETCH_MAX_DEPTH)
			break;

		c = cms_sketch_cell(cur, row,
				    cms_sketch_col(id, cms_sketch_seeds[cur][row]));
		if (c)
			sum += *c;

		p = cms_sketch_cell(prev, row,
				    cms_sketch_col(id, cms_sketch_seeds[prev][row]));
		if (p)
			sum += *p;

		if (sum < best)
			best = sum;
	}

	return best == (u64)-1 ? 0 : best;
}

static __always_inline void cms_sketch_seed_row(u32 buf, u32 row)
{
	if (buf < 2 && row < CMS_SKETCH_MAX_DEPTH)
		cms_sketch_seeds[buf][row] = bpf_get_prandom_u32() | 1;
}

/*
 * Discard the older buffer and begin a new window in it. The buffer being
 * zeroed is the one holding two-windows-ago data, so after the swap the
 * surviving buffer is last window and the freshly cleared one is current.
 */
static __always_inline void cms_sketch_rotate(void)
{
	u32 next = (cms_sketch_cur & 1) ^ 1;
	u32 row, col;

	bpf_for(row, 0, cms_sketch_depth) {
		if (row >= CMS_SKETCH_MAX_DEPTH)
			break;

		bpf_for(col, 0, cms_sketch_width) {
			u32 *cell;

			if (col >= CMS_SKETCH_MAX_WIDTH)
				break;

			cell = cms_sketch_cell(next, row, col);
			if (cell)
				*cell = 0;
		}

		/*
		 * Fresh seeds for the incoming buffer only. The surviving
		 * buffer must keep the seeds its counts were written under or
		 * its cells would be read at the wrong columns.
		 */
		if (cms_seed_rotation)
			cms_sketch_seed_row(next, row);
	}

	cms_sketch_cur = next;
	__sync_fetch_and_add(&cms_sketch_rotations, 1);
}

static __always_inline void cms_sketch_init(void)
{
	u32 row;

	bpf_for(row, 0, cms_sketch_depth) {
		if (row >= CMS_SKETCH_MAX_DEPTH)
			break;

		cms_sketch_seed_row(0, row);
		cms_sketch_seed_row(1, row);
	}
}
