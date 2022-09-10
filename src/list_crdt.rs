use crate::element::*;
use splay_tree::SplaySet;
use std::cmp::max;

pub struct ListCRDT<T> {
    our_id: AuthorID,
    splayset: SplaySet<Element<T>>,
    highest_sequence_number: SequenceNumber,
    size: usize,
}

impl<T> ListCRDT<T>
where
    T: Eq,
{
    pub fn new(id: AuthorID) -> ListCRDT<T> {
        let mut splayset = SplaySet::new();
        splayset.insert(Element {
            id: ROOT_ID,
            origin: None,
            is_deleted: false,
            content: None,
        });
        ListCRDT {
            our_id: id,
            splayset,
            highest_sequence_number: 0,
            size: 0,
        }
    }

    fn find_by_id(&mut self, id: OpID) -> Option<Ref<Element<T>>> {
        // construct a fake element so we can query by id
        let fake_element = Element::ghost_element(id);
        self.splayset.get(&fake_element).map(|elt| elt as Ref<Element<T>> )
    }

    pub fn insert(&mut self, after: OpID, content: T) -> OpID {
        let id = (self.our_id, self.highest_sequence_number + 1);
        let origin = self.find_by_id(after);
        self.insert_remote(Element {
            id,
            origin,
            is_deleted: false,
            content: Some(content),
        });
        id
    }

    pub fn insert_remote(&mut self, elt: Element<T>) {
        let elt_seq_num = elt.sequence_num();
        let elt_is_deleted = elt.is_deleted();
        self.splayset.insert(elt);
        self.highest_sequence_number = max(elt_seq_num, self.highest_sequence_number);
        if !elt_is_deleted {
            self.size += 1;
        }
    }

    pub fn iter(&self) -> Iter<T> {
        Iter {
            inner_iter: self.splayset.iter(),
        }
    }
}

pub struct Iter<'a, T> {
    inner_iter: splay_tree::set::Iter<'a, Element<T>>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(elt) = self.inner_iter.next() {
            if elt.id != ROOT_ID && !elt.is_deleted && elt.content.is_some() {
                return elt.content.as_ref();
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::{ListCRDT, ROOT_ID};

    #[test]
    fn test_basic_doc() {
        let mut doc = ListCRDT::<u16>::new(0);
        let _first_op = doc.insert(ROOT_ID, 0);
        let _second_op = doc.insert(_first_op, 1);
        let _third_op = doc.insert(ROOT_ID, 2);
        assert_eq!(doc.iter().collect::<Vec<_>>(), vec![&2, &0, &1]);
    }
}
