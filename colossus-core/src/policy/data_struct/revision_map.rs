use std::{
    borrow::Borrow,
    collections::{
        HashMap, LinkedList,
        hash_map::{Entry, OccupiedEntry, VacantEntry},
    },
    fmt::Debug,
    hash::Hash,
};

#[derive(Debug, PartialEq, Eq)]
pub struct RevisionMap<K, V>
where
    K: Debug + PartialEq + Eq + Hash,
    V: Debug,
{
    pub(crate) map: HashMap<K, LinkedList<V>>,
}

impl<K, V> Default for RevisionMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
    V: Clone + Debug,
{
    fn default() -> Self {
        Self { map: HashMap::default() }
    }
}

impl<K, V> RevisionMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
    V: Clone + Debug,
{
    #[must_use]
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self { map: HashMap::with_capacity(capacity) }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn count_elements(&self) -> usize {
        self.map.values().map(LinkedList::len).sum()
    }

    pub fn chain_length(&self, key: &K) -> usize {
        self.map.get(key).map_or(0, std::collections::LinkedList::len)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn insert_new_chain(entry: VacantEntry<K, LinkedList<V>>, value: V) {
        let mut new_chain = LinkedList::new();
        new_chain.push_front(value);
        entry.insert(new_chain);
    }

    fn insert_in_chain(mut entry: OccupiedEntry<K, LinkedList<V>>, value: V) {
        let chain = entry.get_mut();
        chain.push_front(value);
    }

    pub fn insert(&mut self, key: K, value: V) {
        match self.map.entry(key) {
            Entry::Occupied(entry) => Self::insert_in_chain(entry, value),
            Entry::Vacant(entry) => Self::insert_new_chain(entry, value),
        }
    }

    pub fn get_latest<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(key).and_then(LinkedList::front)
    }

    pub fn get_latest_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_mut(key).and_then(LinkedList::front_mut)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &LinkedList<V>)> {
        self.map.iter()
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&LinkedList<V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(key) //.map(RevisionList::iter)
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<impl Iterator<Item = V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.remove(key).map(LinkedList::into_iter)
    }

    pub fn keep<Q>(&mut self, key: &Q, n: usize) -> Option<impl Iterator<Item = V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let chain = self.map.get_mut(key)?;
        if n <= chain.len() {
            Some(chain.split_off(n).into_iter())
        } else {
            None
        }
    }

    pub fn retain(&mut self, f: impl Fn(&K) -> bool) {
        self.map.retain(|key, _| f(key));
    }

    pub fn extend(&mut self, with: RevisionMap<K, V>) {
        self.map.extend(with.map);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unnecessary_to_owned)]
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_revision_map() {
        let mut map: RevisionMap<String, String> = RevisionMap::new();
        assert!(map.is_empty());

        map.insert("Part1".to_string(), "Part1V1".to_string());
        assert_eq!(map.count_elements(), 1);
        assert_eq!(map.len(), 1);
        map.insert("Part1".to_string(), "Part1V2".to_string());
        assert_eq!(map.count_elements(), 2);

        assert_eq!(map.len(), 1);

        map.insert("Part2".to_string(), "Part2V1".to_string());
        map.insert("Part2".to_string(), "Part2V2".to_string());
        map.insert("Part2".to_string(), "Part2V3".to_string());
        assert_eq!(map.len(), 2);
        assert_eq!(map.count_elements(), 5);

        map.insert("Part3".to_string(), "Part3V1".to_string());
        assert_eq!(map.count_elements(), 6);

        assert_eq!(map.get_latest("Part1").unwrap(), "Part1V2");
        assert_eq!(map.get_latest("Part2").unwrap(), "Part2V3");
        assert!(map.get_latest("Missing").is_none());

        let vec: Vec<_> = map.get("Part1").unwrap().iter().collect();
        assert_eq!(vec, vec!["Part1V2", "Part1V1"]);

        let keys_set = map.keys().collect::<HashSet<_>>();
        assert!(keys_set.contains(&"Part1".to_string()));
        assert!(keys_set.contains(&"Part2".to_string()));

        let vec: Vec<_> = map.remove("Part1").unwrap().collect();
        assert_eq!(vec, vec!["Part1V2".to_string(), "Part1V1".to_string()]);
        assert_eq!(map.count_elements(), 4);
        assert_eq!(map.len(), 2);

        let vec: Vec<_> = map.keep("Part2", 1).unwrap().collect();
        assert_eq!(vec, vec!["Part2V2".to_string(), "Part2V1".to_string()]);
        assert_eq!(map.count_elements(), 2);
        let vec: Vec<_> = map.remove("Part2").unwrap().collect();
        assert_eq!(vec, vec!["Part2V3".to_string()]);

        assert!(map.keep("Part3", 1).unwrap().next().is_none());

        map.retain(|_| true);
        assert_eq!(map.count_elements(), 1);
        map.retain(|_| false);
        assert!(map.is_empty());
    }
}
