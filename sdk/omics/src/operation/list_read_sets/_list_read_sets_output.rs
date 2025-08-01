// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListReadSetsOutput {
    /// <p>A pagination token that's included if more results are available.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of read sets.</p>
    pub read_sets: ::std::vec::Vec<crate::types::ReadSetListItem>,
    _request_id: Option<String>,
}
impl ListReadSetsOutput {
    /// <p>A pagination token that's included if more results are available.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of read sets.</p>
    pub fn read_sets(&self) -> &[crate::types::ReadSetListItem] {
        use std::ops::Deref;
        self.read_sets.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListReadSetsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListReadSetsOutput {
    /// Creates a new builder-style object to manufacture [`ListReadSetsOutput`](crate::operation::list_read_sets::ListReadSetsOutput).
    pub fn builder() -> crate::operation::list_read_sets::builders::ListReadSetsOutputBuilder {
        crate::operation::list_read_sets::builders::ListReadSetsOutputBuilder::default()
    }
}

/// A builder for [`ListReadSetsOutput`](crate::operation::list_read_sets::ListReadSetsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListReadSetsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) read_sets: ::std::option::Option<::std::vec::Vec<crate::types::ReadSetListItem>>,
    _request_id: Option<String>,
}
impl ListReadSetsOutputBuilder {
    /// <p>A pagination token that's included if more results are available.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pagination token that's included if more results are available.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A pagination token that's included if more results are available.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `read_sets`.
    ///
    /// To override the contents of this collection use [`set_read_sets`](Self::set_read_sets).
    ///
    /// <p>A list of read sets.</p>
    pub fn read_sets(mut self, input: crate::types::ReadSetListItem) -> Self {
        let mut v = self.read_sets.unwrap_or_default();
        v.push(input);
        self.read_sets = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of read sets.</p>
    pub fn set_read_sets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReadSetListItem>>) -> Self {
        self.read_sets = input;
        self
    }
    /// <p>A list of read sets.</p>
    pub fn get_read_sets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReadSetListItem>> {
        &self.read_sets
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListReadSetsOutput`](crate::operation::list_read_sets::ListReadSetsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`read_sets`](crate::operation::list_read_sets::builders::ListReadSetsOutputBuilder::read_sets)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_read_sets::ListReadSetsOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_read_sets::ListReadSetsOutput {
            next_token: self.next_token,
            read_sets: self.read_sets.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "read_sets",
                    "read_sets was not specified but it is required when building ListReadSetsOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
