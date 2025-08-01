// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyDbInstanceOutput {
    /// <p>Detailed information about an instance.</p>
    pub db_instance: ::std::option::Option<crate::types::DbInstance>,
    _request_id: Option<String>,
}
impl ModifyDbInstanceOutput {
    /// <p>Detailed information about an instance.</p>
    pub fn db_instance(&self) -> ::std::option::Option<&crate::types::DbInstance> {
        self.db_instance.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ModifyDbInstanceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyDbInstanceOutput {
    /// Creates a new builder-style object to manufacture [`ModifyDbInstanceOutput`](crate::operation::modify_db_instance::ModifyDbInstanceOutput).
    pub fn builder() -> crate::operation::modify_db_instance::builders::ModifyDbInstanceOutputBuilder {
        crate::operation::modify_db_instance::builders::ModifyDbInstanceOutputBuilder::default()
    }
}

/// A builder for [`ModifyDbInstanceOutput`](crate::operation::modify_db_instance::ModifyDbInstanceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyDbInstanceOutputBuilder {
    pub(crate) db_instance: ::std::option::Option<crate::types::DbInstance>,
    _request_id: Option<String>,
}
impl ModifyDbInstanceOutputBuilder {
    /// <p>Detailed information about an instance.</p>
    pub fn db_instance(mut self, input: crate::types::DbInstance) -> Self {
        self.db_instance = ::std::option::Option::Some(input);
        self
    }
    /// <p>Detailed information about an instance.</p>
    pub fn set_db_instance(mut self, input: ::std::option::Option<crate::types::DbInstance>) -> Self {
        self.db_instance = input;
        self
    }
    /// <p>Detailed information about an instance.</p>
    pub fn get_db_instance(&self) -> &::std::option::Option<crate::types::DbInstance> {
        &self.db_instance
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyDbInstanceOutput`](crate::operation::modify_db_instance::ModifyDbInstanceOutput).
    pub fn build(self) -> crate::operation::modify_db_instance::ModifyDbInstanceOutput {
        crate::operation::modify_db_instance::ModifyDbInstanceOutput {
            db_instance: self.db_instance,
            _request_id: self._request_id,
        }
    }
}
