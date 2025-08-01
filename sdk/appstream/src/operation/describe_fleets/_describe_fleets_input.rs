// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFleetsInput {
    /// <p>The names of the fleets to describe.</p>
    pub names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeFleetsInput {
    /// <p>The names of the fleets to describe.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.names.is_none()`.
    pub fn names(&self) -> &[::std::string::String] {
        self.names.as_deref().unwrap_or_default()
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeFleetsInput {
    /// Creates a new builder-style object to manufacture [`DescribeFleetsInput`](crate::operation::describe_fleets::DescribeFleetsInput).
    pub fn builder() -> crate::operation::describe_fleets::builders::DescribeFleetsInputBuilder {
        crate::operation::describe_fleets::builders::DescribeFleetsInputBuilder::default()
    }
}

/// A builder for [`DescribeFleetsInput`](crate::operation::describe_fleets::DescribeFleetsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFleetsInputBuilder {
    pub(crate) names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeFleetsInputBuilder {
    /// Appends an item to `names`.
    ///
    /// To override the contents of this collection use [`set_names`](Self::set_names).
    ///
    /// <p>The names of the fleets to describe.</p>
    pub fn names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.names.unwrap_or_default();
        v.push(input.into());
        self.names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The names of the fleets to describe.</p>
    pub fn set_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.names = input;
        self
    }
    /// <p>The names of the fleets to describe.</p>
    pub fn get_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.names
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to use to retrieve the next page of results for this operation. If this value is null, it retrieves the first page.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeFleetsInput`](crate::operation::describe_fleets::DescribeFleetsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_fleets::DescribeFleetsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_fleets::DescribeFleetsInput {
            names: self.names,
            next_token: self.next_token,
        })
    }
}
