// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCoipPoolOutput {
    /// <p>Information about the CoIP address pool.</p>
    pub coip_pool: ::std::option::Option<crate::types::CoipPool>,
    _request_id: Option<String>,
}
impl CreateCoipPoolOutput {
    /// <p>Information about the CoIP address pool.</p>
    pub fn coip_pool(&self) -> ::std::option::Option<&crate::types::CoipPool> {
        self.coip_pool.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateCoipPoolOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateCoipPoolOutput {
    /// Creates a new builder-style object to manufacture [`CreateCoipPoolOutput`](crate::operation::create_coip_pool::CreateCoipPoolOutput).
    pub fn builder() -> crate::operation::create_coip_pool::builders::CreateCoipPoolOutputBuilder {
        crate::operation::create_coip_pool::builders::CreateCoipPoolOutputBuilder::default()
    }
}

/// A builder for [`CreateCoipPoolOutput`](crate::operation::create_coip_pool::CreateCoipPoolOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCoipPoolOutputBuilder {
    pub(crate) coip_pool: ::std::option::Option<crate::types::CoipPool>,
    _request_id: Option<String>,
}
impl CreateCoipPoolOutputBuilder {
    /// <p>Information about the CoIP address pool.</p>
    pub fn coip_pool(mut self, input: crate::types::CoipPool) -> Self {
        self.coip_pool = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the CoIP address pool.</p>
    pub fn set_coip_pool(mut self, input: ::std::option::Option<crate::types::CoipPool>) -> Self {
        self.coip_pool = input;
        self
    }
    /// <p>Information about the CoIP address pool.</p>
    pub fn get_coip_pool(&self) -> &::std::option::Option<crate::types::CoipPool> {
        &self.coip_pool
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateCoipPoolOutput`](crate::operation::create_coip_pool::CreateCoipPoolOutput).
    pub fn build(self) -> crate::operation::create_coip_pool::CreateCoipPoolOutput {
        crate::operation::create_coip_pool::CreateCoipPoolOutput {
            coip_pool: self.coip_pool,
            _request_id: self._request_id,
        }
    }
}
