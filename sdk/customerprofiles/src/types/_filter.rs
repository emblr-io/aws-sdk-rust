// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines how to filter the objects coming in for calculated attributes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Filter {
    /// <p>Define whether to include or exclude objects for Calculated Attributed calculation that fit the filter groups criteria.</p>
    pub include: crate::types::Include,
    /// <p>Holds the list of Filter groups within the Filter definition.</p>
    pub groups: ::std::vec::Vec<crate::types::FilterGroup>,
}
impl Filter {
    /// <p>Define whether to include or exclude objects for Calculated Attributed calculation that fit the filter groups criteria.</p>
    pub fn include(&self) -> &crate::types::Include {
        &self.include
    }
    /// <p>Holds the list of Filter groups within the Filter definition.</p>
    pub fn groups(&self) -> &[crate::types::FilterGroup] {
        use std::ops::Deref;
        self.groups.deref()
    }
}
impl Filter {
    /// Creates a new builder-style object to manufacture [`Filter`](crate::types::Filter).
    pub fn builder() -> crate::types::builders::FilterBuilder {
        crate::types::builders::FilterBuilder::default()
    }
}

/// A builder for [`Filter`](crate::types::Filter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilterBuilder {
    pub(crate) include: ::std::option::Option<crate::types::Include>,
    pub(crate) groups: ::std::option::Option<::std::vec::Vec<crate::types::FilterGroup>>,
}
impl FilterBuilder {
    /// <p>Define whether to include or exclude objects for Calculated Attributed calculation that fit the filter groups criteria.</p>
    /// This field is required.
    pub fn include(mut self, input: crate::types::Include) -> Self {
        self.include = ::std::option::Option::Some(input);
        self
    }
    /// <p>Define whether to include or exclude objects for Calculated Attributed calculation that fit the filter groups criteria.</p>
    pub fn set_include(mut self, input: ::std::option::Option<crate::types::Include>) -> Self {
        self.include = input;
        self
    }
    /// <p>Define whether to include or exclude objects for Calculated Attributed calculation that fit the filter groups criteria.</p>
    pub fn get_include(&self) -> &::std::option::Option<crate::types::Include> {
        &self.include
    }
    /// Appends an item to `groups`.
    ///
    /// To override the contents of this collection use [`set_groups`](Self::set_groups).
    ///
    /// <p>Holds the list of Filter groups within the Filter definition.</p>
    pub fn groups(mut self, input: crate::types::FilterGroup) -> Self {
        let mut v = self.groups.unwrap_or_default();
        v.push(input);
        self.groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>Holds the list of Filter groups within the Filter definition.</p>
    pub fn set_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FilterGroup>>) -> Self {
        self.groups = input;
        self
    }
    /// <p>Holds the list of Filter groups within the Filter definition.</p>
    pub fn get_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FilterGroup>> {
        &self.groups
    }
    /// Consumes the builder and constructs a [`Filter`](crate::types::Filter).
    /// This method will fail if any of the following fields are not set:
    /// - [`include`](crate::types::builders::FilterBuilder::include)
    /// - [`groups`](crate::types::builders::FilterBuilder::groups)
    pub fn build(self) -> ::std::result::Result<crate::types::Filter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Filter {
            include: self.include.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "include",
                    "include was not specified but it is required when building Filter",
                )
            })?,
            groups: self.groups.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "groups",
                    "groups was not specified but it is required when building Filter",
                )
            })?,
        })
    }
}
