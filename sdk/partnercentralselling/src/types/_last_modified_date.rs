// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a filter to retrieve opportunities based on the last modified date. This filter is useful for tracking changes or updates to opportunities over time.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LastModifiedDate {
    /// <p>Specifies the date after which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified after a given timestamp.</p>
    pub after_last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Specifies the date before which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified before a given timestamp.</p>
    pub before_last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl LastModifiedDate {
    /// <p>Specifies the date after which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified after a given timestamp.</p>
    pub fn after_last_modified_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.after_last_modified_date.as_ref()
    }
    /// <p>Specifies the date before which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified before a given timestamp.</p>
    pub fn before_last_modified_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.before_last_modified_date.as_ref()
    }
}
impl LastModifiedDate {
    /// Creates a new builder-style object to manufacture [`LastModifiedDate`](crate::types::LastModifiedDate).
    pub fn builder() -> crate::types::builders::LastModifiedDateBuilder {
        crate::types::builders::LastModifiedDateBuilder::default()
    }
}

/// A builder for [`LastModifiedDate`](crate::types::LastModifiedDate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LastModifiedDateBuilder {
    pub(crate) after_last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) before_last_modified_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl LastModifiedDateBuilder {
    /// <p>Specifies the date after which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified after a given timestamp.</p>
    pub fn after_last_modified_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.after_last_modified_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the date after which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified after a given timestamp.</p>
    pub fn set_after_last_modified_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.after_last_modified_date = input;
        self
    }
    /// <p>Specifies the date after which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified after a given timestamp.</p>
    pub fn get_after_last_modified_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.after_last_modified_date
    }
    /// <p>Specifies the date before which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified before a given timestamp.</p>
    pub fn before_last_modified_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.before_last_modified_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the date before which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified before a given timestamp.</p>
    pub fn set_before_last_modified_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.before_last_modified_date = input;
        self
    }
    /// <p>Specifies the date before which the opportunities were modified. Use this filter to retrieve only those opportunities that were modified before a given timestamp.</p>
    pub fn get_before_last_modified_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.before_last_modified_date
    }
    /// Consumes the builder and constructs a [`LastModifiedDate`](crate::types::LastModifiedDate).
    pub fn build(self) -> crate::types::LastModifiedDate {
        crate::types::LastModifiedDate {
            after_last_modified_date: self.after_last_modified_date,
            before_last_modified_date: self.before_last_modified_date,
        }
    }
}
