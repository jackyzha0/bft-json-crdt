use splay_tree::SplaySet;
use std::cmp::max;
use std::cmp::Ordering;
use std::rc::Weak;

type AuthorID = u64;
type SequenceNumber = u64;
type OpID = (AuthorID, SequenceNumber);

pub struct Element<T> {
    id: OpID,
    origin: Option<Weak<Element<T>>>,
    is_deleted: bool,
    content: Option<T>,
}

impl<T> Element<T> {
    pub fn author(&self) -> AuthorID {
        self.id.0
    }

    pub fn sequence_num(&self) -> SequenceNumber {
        self.id.1
    }

    pub fn ghost_element(with_id: OpID) -> Element<T> {
        Element {
            id: with_id,
            origin: None,
            is_deleted: false,
            content: None,
        }
    }

    pub fn origin_deref(&self) -> Option<&Element<T>> {
        self.origin
            .as_ref()
            .map(|origin| unsafe { &*origin.as_ptr() })
    }
}
const ROOT_ID: OpID = (0, 0);

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

    fn find_by_id(&mut self, id: OpID) -> Option<Weak<Element<T>>> {
        // construct a fake element so we can query by id
        let fake_element = Element::ghost_element(id);
        self.splayset.get(&fake_element).map(|elt| {
            let node: *const Element<T> = elt;
            unsafe { Weak::from_raw(node) }
        })
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

    pub fn delete(&mut self, id: OpID) {
        self.insert_remote(Element {
            id,
            origin: None,
            is_deleted: true,
            content: None,
        })
    }

    pub fn insert_remote(&mut self, elt: Element<T>) {
        let elt_seq_num = elt.sequence_num();
        let elt_is_deleted = elt.is_deleted;
        println!("insert -> {:?}", elt.id);
        self.splayset.insert(elt);
        self.highest_sequence_number = max(elt_seq_num, self.highest_sequence_number);
        if !elt_is_deleted {
            self.size += 1;
        }
    }

    pub fn iter<'a>(&'a self) -> Iter<'a, T> {
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

impl<T> PartialEq for Element<T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<T> Eq for Element<T> {}

impl<T> Ord for Element<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // if we have a bigger sequence number, we are bigger
        if self.sequence_num() > other.sequence_num() {
            return Ordering::Greater;
        }

        // if index of our parent is > than the index of other parent, we are bigger
        let our_origin = self.origin_deref();
        let other_origin = other.origin_deref();
        match our_origin.cmp(&other_origin) {
            Ordering::Greater => Ordering::Greater,
            Ordering::Less => Ordering::Less,
            Ordering::Equal => {
                // parents are equal, is sequence number the same?
                if self.sequence_num() == other.sequence_num() {
                    // tie break on author id
                    self.author().cmp(&other.author())
                } else {
                    // if sequence number is not > or == then it must be <
                    Ordering::Less
                }
            }
        }
    }
}

impl<T> PartialOrd for Element<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod test {
    use super::{ListCRDT, ROOT_ID};

    #[test]
    fn test_basic_doc() {
        let mut doc = ListCRDT::<u16>::new(0);
        let first_op = doc.insert(ROOT_ID, 0);
        let second_op = doc.insert(first_op, 1);
        let third_op = doc.insert(ROOT_ID, 2);
        assert_eq!(doc.iter().collect::<Vec<_>>(), vec![&2, &0, &1]);
    }
}
