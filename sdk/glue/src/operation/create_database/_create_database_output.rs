// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDatabaseOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for CreateDatabaseOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateDatabaseOutput {
    /// Creates a new builder-style object to manufacture [`CreateDatabaseOutput`](crate::operation::create_database::CreateDatabaseOutput).
    pub fn builder() -> crate::operation::create_database::builders::CreateDatabaseOutputBuilder {
        crate::operation::create_database::builders::CreateDatabaseOutputBuilder::default()
    }
}

/// A builder for [`CreateDatabaseOutput`](crate::operation::create_database::CreateDatabaseOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDatabaseOutputBuilder {
    _request_id: Option<String>,
}
impl CreateDatabaseOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateDatabaseOutput`](crate::operation::create_database::CreateDatabaseOutput).
    pub fn build(self) -> crate::operation::create_database::CreateDatabaseOutput {
        crate::operation::create_database::CreateDatabaseOutput {
            _request_id: self._request_id,
        }
    }
}
