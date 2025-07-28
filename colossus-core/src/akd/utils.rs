use alloc::vec::Vec;

const MARKER_VERSION_SKIPLIST: [u64; 7] = [1, 1 << 1, 1 << 2, 1 << 4, 1 << 8, 1 << 16, 1 << 32];

pub type PastMarkerVersions = Vec<u64>;

pub type FutureMarkerVersions = Vec<u64>;

pub fn get_marker_version_log2(version: u64) -> u64 {
    assert!(version != 0, "get_marker_version_log2 called with version = 0");
    64 - (version.leading_zeros() as u64) - 1
}

fn get_bit_length(input: u64) -> u64 {
    let leading_zeros = input.leading_zeros() as u64;
    if leading_zeros > 64 {
        panic!("get_bit_length input has more than 64 leading zeros");
    }
    64 - leading_zeros
}

pub fn get_marker_versions(
    start_version: u64,
    end_version: u64,
    epoch: u64,
) -> (PastMarkerVersions, FutureMarkerVersions) {
    let mut past_marker_versions: Vec<u64> = Vec::new();

    let skiplist_past_index: usize = find_max_index_in_skiplist(start_version);
    if MARKER_VERSION_SKIPLIST[skiplist_past_index] != start_version {
        past_marker_versions.push(MARKER_VERSION_SKIPLIST[skiplist_past_index]);
    }
    let start_version_log2 = 1 << get_marker_version_log2(start_version);
    if start_version_log2 != start_version
        && (past_marker_versions.is_empty()
            || start_version_log2 != past_marker_versions[past_marker_versions.len() - 1])
    {
        past_marker_versions.push(start_version_log2);
    }

    let start_version_length = get_bit_length(start_version);
    for i in (0..start_version_length).rev() {
        let shift = 1 << i;

        if start_version & shift != 0 {
            let shift_mask = (shift - 1) | shift;
            let past_version = start_version & !shift_mask;
            if past_version != 0
                && (past_marker_versions.is_empty()
                    || past_version != past_marker_versions[past_marker_versions.len() - 1])
            {
                past_marker_versions.push(past_version);
            }
        }
    }

    let mut future_marker_versions: Vec<u64> = Vec::new();

    let end_version_length = get_bit_length(end_version);
    let mut future_version: u64 = end_version;
    for i in 0..end_version_length {
        let shift = 1 << i;

        if end_version & shift == 0 {
            future_version |= shift;
            future_version &= !(shift - 1);
            if future_version <= epoch {
                future_marker_versions.push(future_version);
            }
        }
    }

    let endv_index: usize = find_max_index_in_skiplist(end_version);
    let epoch_index: usize = find_max_index_in_skiplist(epoch);
    let skiplist_slice = &MARKER_VERSION_SKIPLIST[endv_index + 1_usize..epoch_index + 1_usize];

    let next_marker_log2 = get_marker_version_log2(end_version) + 1;
    let final_marker_log2 = get_marker_version_log2(epoch);
    for i in next_marker_log2..(final_marker_log2 + 1) {
        let val = 1 << i;
        if !skiplist_slice.is_empty() && val >= skiplist_slice[0] {
            break;
        }
        future_marker_versions.push(1 << i);
    }
    future_marker_versions.extend_from_slice(skiplist_slice);

    (past_marker_versions, future_marker_versions)
}

fn find_max_index_in_skiplist(input: u64) -> usize {
    if input < MARKER_VERSION_SKIPLIST[0] {
        panic!(
            "find_max_index_in_skiplist called with input less than smallest element of MARKER_VERSION_SKIPLIST"
        );
    }
    let mut i = 0;
    while i < MARKER_VERSION_SKIPLIST.len() {
        if input < MARKER_VERSION_SKIPLIST[i] {
            break;
        }
        i += 1;
    }
    i - 1
}

pub fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

pub fn i2osp_array(input: &[u8]) -> Vec<u8> {
    [&(input.len() as u64).to_be_bytes(), input].concat()
}

#[allow(unused)]
pub(crate) fn random_label(rng: &mut impl rand::Rng) -> crate::akd::NodeLabel {
    crate::akd::NodeLabel {
        label_val: rng.random::<[u8; 32]>(),
        label_len: 256,
    }
}

#[macro_export]
macro_rules! test_config_sync {
    ( $x:ident ) => {
        paste::paste! {
            #[test]
            fn [<$x _ colossus_config>]() {
                $x::<$crate::configuration::ColossusConfiguration<$crate::configuration::ExampleLabel>>()
            }
        }
    };
}

#[macro_export]
macro_rules! test_config {
    ( $x:ident ) => {
        paste::paste! {
            #[tokio::test]
            async fn [<$x _ colossus_config>]() -> Result<(), AkdError> {
                $x::<$crate::configuration::ColossusConfiguration<$crate::configuration::ExampleLabel>>().await
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    #[test]
    fn test_get_marker_versions() {
        assert_eq!((vec![16, 64], vec![66, 68, 72, 80, 96, 128]), get_marker_versions(65, 65, 128));
        assert_eq!(
            (vec![16, 64, 80, 84], vec![86, 88, 96, 128, 256, 65536]),
            get_marker_versions(85, 85, 65537)
        );
        assert_eq!((vec![], vec![6, 8, 16]), get_marker_versions(1, 5, 33));

        assert_eq!((vec![], vec![6, 8, 16]), get_marker_versions(2, 5, 33));

        assert_eq!((vec![2], vec![6, 8, 16]), get_marker_versions(3, 5, 33));

        assert_eq!((vec![4], vec![13, 14, 16]), get_marker_versions(6, 12, 128));

        assert_eq!((vec![4], vec![13, 14, 16, 256]), get_marker_versions(6, 12, 256));

        assert_eq!(
            (vec![16, 128], vec![131, 132, 136, 144, 160, 192, 256]),
            get_marker_versions(130, 130, 256)
        );
    }

    #[derive(Clone)]
    enum RangeType {
        Small,
        Medium,
        Large,
    }

    fn gen_versions(
        rng: &mut StdRng,
        start_type: &RangeType,
        end_type: &RangeType,
        epoch_type: &RangeType,
    ) -> (u64, u64, u64) {
        let small_jump = 10;
        let medium_jump = 1000;
        let start_version: u64 = rng.random_range(match start_type {
            RangeType::Small => 1..small_jump,
            RangeType::Medium => 1..medium_jump,
            RangeType::Large => 1..u64::MAX - 2 * (small_jump + medium_jump),
        });
        let end_version: u64 = rng.random_range(match end_type {
            RangeType::Small => start_version..start_version + small_jump,
            RangeType::Medium => start_version..start_version + medium_jump,
            RangeType::Large => start_version..u64::MAX - small_jump - medium_jump,
        });
        let epoch: u64 = rng.random_range(match epoch_type {
            RangeType::Small => end_version..end_version + small_jump,
            RangeType::Medium => end_version..end_version + medium_jump,
            RangeType::Large => end_version..u64::MAX,
        });
        (start_version, end_version, epoch)
    }

    #[test]
    fn test_marker_version_invariants() {
        let iterations = 10000;
        let options = [RangeType::Small, RangeType::Medium, RangeType::Large];
        let mut rng = StdRng::from_os_rng();
        for (start_type, end_type, epoch_type) in itertools::iproduct!(&options, &options, &options)
        {
            for _ in 0..iterations {
                let (start_version, end_version, epoch) =
                    gen_versions(&mut rng, start_type, end_type, epoch_type);

                let (past_versions, future_versions) =
                    get_marker_versions(start_version, end_version, epoch);

                for version in past_versions.iter() {
                    assert!(version < &start_version);
                }

                for version in future_versions.iter() {
                    assert!(version > &end_version);
                }

                for version in future_versions.iter() {
                    assert!(version <= &epoch);
                }

                let mut past_versions_sorted = past_versions.clone();
                past_versions_sorted.sort();
                assert!(past_versions_sorted == past_versions);
                past_versions_sorted.dedup();
                assert_eq!(past_versions_sorted.len(), past_versions.len());

                let mut future_versions_sorted = future_versions.clone();
                future_versions_sorted.sort();
                assert!(future_versions_sorted == future_versions);
                future_versions_sorted.dedup();
                assert_eq!(future_versions_sorted.len(), future_versions.len());
            }
        }
    }
}
