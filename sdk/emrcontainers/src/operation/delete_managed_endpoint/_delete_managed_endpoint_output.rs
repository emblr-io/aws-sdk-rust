// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteManagedEndpointOutput {
    /// <p>The output displays the ID of the managed endpoint.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The output displays the ID of the endpoint's virtual cluster.</p>
    pub virtual_cluster_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteManagedEndpointOutput {
    /// <p>The output displays the ID of the managed endpoint.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The output displays the ID of the endpoint's virtual cluster.</p>
    pub fn virtual_cluster_id(&self) -> ::std::option::Option<&str> {
        self.virtual_cluster_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteManagedEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteManagedEndpointOutput {
    /// Creates a new builder-style object to manufacture [`DeleteManagedEndpointOutput`](crate::operation::delete_managed_endpoint::DeleteManagedEndpointOutput).
    pub fn builder() -> crate::operation::delete_managed_endpoint::builders::DeleteManagedEndpointOutputBuilder {
        crate::operation::delete_managed_endpoint::builders::DeleteManagedEndpointOutputBuilder::default()
    }
}

/// A builder for [`DeleteManagedEndpointOutput`](crate::operation::delete_managed_endpoint::DeleteManagedEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteManagedEndpointOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) virtual_cluster_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteManagedEndpointOutputBuilder {
    /// <p>The output displays the ID of the managed endpoint.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The output displays the ID of the managed endpoint.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The output displays the ID of the managed endpoint.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The output displays the ID of the endpoint's virtual cluster.</p>
    pub fn virtual_cluster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_cluster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The output displays the ID of the endpoint's virtual cluster.</p>
    pub fn set_virtual_cluster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_cluster_id = input;
        self
    }
    /// <p>The output displays the ID of the endpoint's virtual cluster.</p>
    pub fn get_virtual_cluster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_cluster_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteManagedEndpointOutput`](crate::operation::delete_managed_endpoint::DeleteManagedEndpointOutput).
    pub fn build(self) -> crate::operation::delete_managed_endpoint::DeleteManagedEndpointOutput {
        crate::operation::delete_managed_endpoint::DeleteManagedEndpointOutput {
            id: self.id,
            virtual_cluster_id: self.virtual_cluster_id,
            _request_id: self._request_id,
        }
    }
}
