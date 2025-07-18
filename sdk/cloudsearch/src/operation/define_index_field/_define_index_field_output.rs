// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a <code><code>DefineIndexField</code></code> request. Contains the status of the newly-configured index field.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DefineIndexFieldOutput {
    /// <p>The value of an <code>IndexField</code> and its current status.</p>
    pub index_field: ::std::option::Option<crate::types::IndexFieldStatus>,
    _request_id: Option<String>,
}
impl DefineIndexFieldOutput {
    /// <p>The value of an <code>IndexField</code> and its current status.</p>
    pub fn index_field(&self) -> ::std::option::Option<&crate::types::IndexFieldStatus> {
        self.index_field.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DefineIndexFieldOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DefineIndexFieldOutput {
    /// Creates a new builder-style object to manufacture [`DefineIndexFieldOutput`](crate::operation::define_index_field::DefineIndexFieldOutput).
    pub fn builder() -> crate::operation::define_index_field::builders::DefineIndexFieldOutputBuilder {
        crate::operation::define_index_field::builders::DefineIndexFieldOutputBuilder::default()
    }
}

/// A builder for [`DefineIndexFieldOutput`](crate::operation::define_index_field::DefineIndexFieldOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DefineIndexFieldOutputBuilder {
    pub(crate) index_field: ::std::option::Option<crate::types::IndexFieldStatus>,
    _request_id: Option<String>,
}
impl DefineIndexFieldOutputBuilder {
    /// <p>The value of an <code>IndexField</code> and its current status.</p>
    /// This field is required.
    pub fn index_field(mut self, input: crate::types::IndexFieldStatus) -> Self {
        self.index_field = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of an <code>IndexField</code> and its current status.</p>
    pub fn set_index_field(mut self, input: ::std::option::Option<crate::types::IndexFieldStatus>) -> Self {
        self.index_field = input;
        self
    }
    /// <p>The value of an <code>IndexField</code> and its current status.</p>
    pub fn get_index_field(&self) -> &::std::option::Option<crate::types::IndexFieldStatus> {
        &self.index_field
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DefineIndexFieldOutput`](crate::operation::define_index_field::DefineIndexFieldOutput).
    pub fn build(self) -> crate::operation::define_index_field::DefineIndexFieldOutput {
        crate::operation::define_index_field::DefineIndexFieldOutput {
            index_field: self.index_field,
            _request_id: self._request_id,
        }
    }
}
