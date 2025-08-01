// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The row filter expression.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum RowFilterExpression {
    /// <p>The 'equal to' clause of the row filter expression.</p>
    EqualTo(crate::types::EqualToExpression),
    /// <p>The 'greater than' clause of the row filter expression.</p>
    GreaterThan(crate::types::GreaterThanExpression),
    /// <p>The 'greater than or equal to' clause of the filter expression.</p>
    GreaterThanOrEqualTo(crate::types::GreaterThanOrEqualToExpression),
    /// <p>The 'in' clause of the row filter expression.</p>
    In(crate::types::InExpression),
    /// <p>The 'is not null' clause of the row filter expression.</p>
    IsNotNull(crate::types::IsNotNullExpression),
    /// <p>The 'is null' clause of the row filter expression.</p>
    IsNull(crate::types::IsNullExpression),
    /// <p>The 'less than' clause of the row filter expression.</p>
    LessThan(crate::types::LessThanExpression),
    /// <p>The 'less than or equal to' clause of the row filter expression.</p>
    LessThanOrEqualTo(crate::types::LessThanOrEqualToExpression),
    /// <p>The 'like' clause of the row filter expression.</p>
    Like(crate::types::LikeExpression),
    /// <p>The 'no equal to' clause of the row filter expression.</p>
    NotEqualTo(crate::types::NotEqualToExpression),
    /// <p>The 'not in' clause of the row filter expression.</p>
    NotIn(crate::types::NotInExpression),
    /// <p>The 'not like' clause of the row filter expression.</p>
    NotLike(crate::types::NotLikeExpression),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl RowFilterExpression {
    /// Tries to convert the enum instance into [`EqualTo`](crate::types::RowFilterExpression::EqualTo), extracting the inner [`EqualToExpression`](crate::types::EqualToExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_equal_to(&self) -> ::std::result::Result<&crate::types::EqualToExpression, &Self> {
        if let RowFilterExpression::EqualTo(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`EqualTo`](crate::types::RowFilterExpression::EqualTo).
    pub fn is_equal_to(&self) -> bool {
        self.as_equal_to().is_ok()
    }
    /// Tries to convert the enum instance into [`GreaterThan`](crate::types::RowFilterExpression::GreaterThan), extracting the inner [`GreaterThanExpression`](crate::types::GreaterThanExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_greater_than(&self) -> ::std::result::Result<&crate::types::GreaterThanExpression, &Self> {
        if let RowFilterExpression::GreaterThan(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`GreaterThan`](crate::types::RowFilterExpression::GreaterThan).
    pub fn is_greater_than(&self) -> bool {
        self.as_greater_than().is_ok()
    }
    /// Tries to convert the enum instance into [`GreaterThanOrEqualTo`](crate::types::RowFilterExpression::GreaterThanOrEqualTo), extracting the inner [`GreaterThanOrEqualToExpression`](crate::types::GreaterThanOrEqualToExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_greater_than_or_equal_to(&self) -> ::std::result::Result<&crate::types::GreaterThanOrEqualToExpression, &Self> {
        if let RowFilterExpression::GreaterThanOrEqualTo(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`GreaterThanOrEqualTo`](crate::types::RowFilterExpression::GreaterThanOrEqualTo).
    pub fn is_greater_than_or_equal_to(&self) -> bool {
        self.as_greater_than_or_equal_to().is_ok()
    }
    /// Tries to convert the enum instance into [`In`](crate::types::RowFilterExpression::In), extracting the inner [`InExpression`](crate::types::InExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_in(&self) -> ::std::result::Result<&crate::types::InExpression, &Self> {
        if let RowFilterExpression::In(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`In`](crate::types::RowFilterExpression::In).
    pub fn is_in(&self) -> bool {
        self.as_in().is_ok()
    }
    /// Tries to convert the enum instance into [`IsNotNull`](crate::types::RowFilterExpression::IsNotNull), extracting the inner [`IsNotNullExpression`](crate::types::IsNotNullExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_is_not_null(&self) -> ::std::result::Result<&crate::types::IsNotNullExpression, &Self> {
        if let RowFilterExpression::IsNotNull(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`IsNotNull`](crate::types::RowFilterExpression::IsNotNull).
    pub fn is_is_not_null(&self) -> bool {
        self.as_is_not_null().is_ok()
    }
    /// Tries to convert the enum instance into [`IsNull`](crate::types::RowFilterExpression::IsNull), extracting the inner [`IsNullExpression`](crate::types::IsNullExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_is_null(&self) -> ::std::result::Result<&crate::types::IsNullExpression, &Self> {
        if let RowFilterExpression::IsNull(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`IsNull`](crate::types::RowFilterExpression::IsNull).
    pub fn is_is_null(&self) -> bool {
        self.as_is_null().is_ok()
    }
    /// Tries to convert the enum instance into [`LessThan`](crate::types::RowFilterExpression::LessThan), extracting the inner [`LessThanExpression`](crate::types::LessThanExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_less_than(&self) -> ::std::result::Result<&crate::types::LessThanExpression, &Self> {
        if let RowFilterExpression::LessThan(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`LessThan`](crate::types::RowFilterExpression::LessThan).
    pub fn is_less_than(&self) -> bool {
        self.as_less_than().is_ok()
    }
    /// Tries to convert the enum instance into [`LessThanOrEqualTo`](crate::types::RowFilterExpression::LessThanOrEqualTo), extracting the inner [`LessThanOrEqualToExpression`](crate::types::LessThanOrEqualToExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_less_than_or_equal_to(&self) -> ::std::result::Result<&crate::types::LessThanOrEqualToExpression, &Self> {
        if let RowFilterExpression::LessThanOrEqualTo(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`LessThanOrEqualTo`](crate::types::RowFilterExpression::LessThanOrEqualTo).
    pub fn is_less_than_or_equal_to(&self) -> bool {
        self.as_less_than_or_equal_to().is_ok()
    }
    /// Tries to convert the enum instance into [`Like`](crate::types::RowFilterExpression::Like), extracting the inner [`LikeExpression`](crate::types::LikeExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_like(&self) -> ::std::result::Result<&crate::types::LikeExpression, &Self> {
        if let RowFilterExpression::Like(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Like`](crate::types::RowFilterExpression::Like).
    pub fn is_like(&self) -> bool {
        self.as_like().is_ok()
    }
    /// Tries to convert the enum instance into [`NotEqualTo`](crate::types::RowFilterExpression::NotEqualTo), extracting the inner [`NotEqualToExpression`](crate::types::NotEqualToExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_not_equal_to(&self) -> ::std::result::Result<&crate::types::NotEqualToExpression, &Self> {
        if let RowFilterExpression::NotEqualTo(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`NotEqualTo`](crate::types::RowFilterExpression::NotEqualTo).
    pub fn is_not_equal_to(&self) -> bool {
        self.as_not_equal_to().is_ok()
    }
    /// Tries to convert the enum instance into [`NotIn`](crate::types::RowFilterExpression::NotIn), extracting the inner [`NotInExpression`](crate::types::NotInExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_not_in(&self) -> ::std::result::Result<&crate::types::NotInExpression, &Self> {
        if let RowFilterExpression::NotIn(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`NotIn`](crate::types::RowFilterExpression::NotIn).
    pub fn is_not_in(&self) -> bool {
        self.as_not_in().is_ok()
    }
    /// Tries to convert the enum instance into [`NotLike`](crate::types::RowFilterExpression::NotLike), extracting the inner [`NotLikeExpression`](crate::types::NotLikeExpression).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_not_like(&self) -> ::std::result::Result<&crate::types::NotLikeExpression, &Self> {
        if let RowFilterExpression::NotLike(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`NotLike`](crate::types::RowFilterExpression::NotLike).
    pub fn is_not_like(&self) -> bool {
        self.as_not_like().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
