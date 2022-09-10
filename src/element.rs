use std::cmp::Ordering;

pub type AuthorID = u8;
pub type SequenceNumber = u64;
pub type OpID = (AuthorID, SequenceNumber);

pub type Ref<T> = *const T; 
pub struct Element<T> {
    pub(crate) id: OpID,
    pub(crate) origin: Option<Ref<Element<T>>>,
    pub(crate) is_deleted: bool,
    pub(crate) content: Option<T>,
}

impl<T> Element<T> {
    pub fn author(&self) -> AuthorID {
        self.id.0
    }

    pub fn sequence_num(&self) -> SequenceNumber {
        self.id.1
    }

    pub fn is_deleted(&self) -> bool {
        self.is_deleted
    }

    pub fn ghost_element(with_id: OpID) -> Element<T> {
        Element {
            id: with_id,
            origin: None,
            is_deleted: false,
            content: None,
        }
    }

    pub fn origin_deref(&self) -> Option<Ref<Element<T>>> {
        self.origin
            .as_ref()
            .map(|origin| *origin )
    }
}

pub const ROOT_ID: OpID = (0, 0);

impl<T> PartialEq for Element<T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<T> Eq for Element<T> {}

impl<T> Ord for Element<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.id == other.id {
            return Ordering::Equal;
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

impl< T> PartialOrd for Element<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

