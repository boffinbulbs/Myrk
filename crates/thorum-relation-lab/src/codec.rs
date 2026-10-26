use crate::RelationError;

/// Bounded callers supply a complete public capability or private opening slice.
pub(crate) struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub(crate) fn field(&mut self) -> Result<&'a [u8], RelationError> {
        let prefix: [u8; 4] = self
            .remaining
            .get(..4)
            .ok_or(RelationError::InvalidEncoding)?
            .try_into()
            .map_err(|_| RelationError::InvalidEncoding)?;
        let length = usize::try_from(u32::from_be_bytes(prefix))
            .map_err(|_| RelationError::InvalidEncoding)?;
        let rest = &self.remaining[4..];
        let value = rest.get(..length).ok_or(RelationError::InvalidEncoding)?;
        self.remaining = &rest[length..];
        Ok(value)
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], RelationError> {
        self.field()?
            .try_into()
            .map_err(|_| RelationError::InvalidEncoding)
    }

    pub(crate) fn finish(self) -> Result<(), RelationError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(RelationError::InvalidEncoding)
        }
    }
}
