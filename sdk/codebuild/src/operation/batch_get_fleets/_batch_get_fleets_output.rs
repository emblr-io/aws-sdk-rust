// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetFleetsOutput {
    /// <p>Information about the requested compute fleets.</p>
    pub fleets: ::std::option::Option<::std::vec::Vec<crate::types::Fleet>>,
    /// <p>The names of compute fleets for which information could not be found.</p>
    pub fleets_not_found: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl BatchGetFleetsOutput {
    /// <p>Information about the requested compute fleets.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fleets.is_none()`.
    pub fn fleets(&self) -> &[crate::types::Fleet] {
        self.fleets.as_deref().unwrap_or_default()
    }
    /// <p>The names of compute fleets for which information could not be found.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fleets_not_found.is_none()`.
    pub fn fleets_not_found(&self) -> &[::std::string::String] {
        self.fleets_not_found.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for BatchGetFleetsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchGetFleetsOutput {
    /// Creates a new builder-style object to manufacture [`BatchGetFleetsOutput`](crate::operation::batch_get_fleets::BatchGetFleetsOutput).
    pub fn builder() -> crate::operation::batch_get_fleets::builders::BatchGetFleetsOutputBuilder {
        crate::operation::batch_get_fleets::builders::BatchGetFleetsOutputBuilder::default()
    }
}

/// A builder for [`BatchGetFleetsOutput`](crate::operation::batch_get_fleets::BatchGetFleetsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetFleetsOutputBuilder {
    pub(crate) fleets: ::std::option::Option<::std::vec::Vec<crate::types::Fleet>>,
    pub(crate) fleets_not_found: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl BatchGetFleetsOutputBuilder {
    /// Appends an item to `fleets`.
    ///
    /// To override the contents of this collection use [`set_fleets`](Self::set_fleets).
    ///
    /// <p>Information about the requested compute fleets.</p>
    pub fn fleets(mut self, input: crate::types::Fleet) -> Self {
        let mut v = self.fleets.unwrap_or_default();
        v.push(input);
        self.fleets = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the requested compute fleets.</p>
    pub fn set_fleets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Fleet>>) -> Self {
        self.fleets = input;
        self
    }
    /// <p>Information about the requested compute fleets.</p>
    pub fn get_fleets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Fleet>> {
        &self.fleets
    }
    /// Appends an item to `fleets_not_found`.
    ///
    /// To override the contents of this collection use [`set_fleets_not_found`](Self::set_fleets_not_found).
    ///
    /// <p>The names of compute fleets for which information could not be found.</p>
    pub fn fleets_not_found(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.fleets_not_found.unwrap_or_default();
        v.push(input.into());
        self.fleets_not_found = ::std::option::Option::Some(v);
        self
    }
    /// <p>The names of compute fleets for which information could not be found.</p>
    pub fn set_fleets_not_found(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.fleets_not_found = input;
        self
    }
    /// <p>The names of compute fleets for which information could not be found.</p>
    pub fn get_fleets_not_found(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.fleets_not_found
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchGetFleetsOutput`](crate::operation::batch_get_fleets::BatchGetFleetsOutput).
    pub fn build(self) -> crate::operation::batch_get_fleets::BatchGetFleetsOutput {
        crate::operation::batch_get_fleets::BatchGetFleetsOutput {
            fleets: self.fleets,
            fleets_not_found: self.fleets_not_found,
            _request_id: self._request_id,
        }
    }
}
