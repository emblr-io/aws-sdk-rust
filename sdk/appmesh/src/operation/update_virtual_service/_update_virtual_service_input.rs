// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateVirtualServiceInput {
    /// <p>The name of the virtual service to update.</p>
    pub virtual_service_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the service mesh that the virtual service resides in.</p>
    pub mesh_name: ::std::option::Option<::std::string::String>,
    /// <p>The new virtual service specification to apply. This overwrites the existing data.</p>
    pub spec: ::std::option::Option<crate::types::VirtualServiceSpec>,
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Up to 36 letters, numbers, hyphens, and underscores are allowed.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then it's the ID of the account that shared the mesh with your account. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub mesh_owner: ::std::option::Option<::std::string::String>,
}
impl UpdateVirtualServiceInput {
    /// <p>The name of the virtual service to update.</p>
    pub fn virtual_service_name(&self) -> ::std::option::Option<&str> {
        self.virtual_service_name.as_deref()
    }
    /// <p>The name of the service mesh that the virtual service resides in.</p>
    pub fn mesh_name(&self) -> ::std::option::Option<&str> {
        self.mesh_name.as_deref()
    }
    /// <p>The new virtual service specification to apply. This overwrites the existing data.</p>
    pub fn spec(&self) -> ::std::option::Option<&crate::types::VirtualServiceSpec> {
        self.spec.as_ref()
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Up to 36 letters, numbers, hyphens, and underscores are allowed.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then it's the ID of the account that shared the mesh with your account. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub fn mesh_owner(&self) -> ::std::option::Option<&str> {
        self.mesh_owner.as_deref()
    }
}
impl UpdateVirtualServiceInput {
    /// Creates a new builder-style object to manufacture [`UpdateVirtualServiceInput`](crate::operation::update_virtual_service::UpdateVirtualServiceInput).
    pub fn builder() -> crate::operation::update_virtual_service::builders::UpdateVirtualServiceInputBuilder {
        crate::operation::update_virtual_service::builders::UpdateVirtualServiceInputBuilder::default()
    }
}

/// A builder for [`UpdateVirtualServiceInput`](crate::operation::update_virtual_service::UpdateVirtualServiceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateVirtualServiceInputBuilder {
    pub(crate) virtual_service_name: ::std::option::Option<::std::string::String>,
    pub(crate) mesh_name: ::std::option::Option<::std::string::String>,
    pub(crate) spec: ::std::option::Option<crate::types::VirtualServiceSpec>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) mesh_owner: ::std::option::Option<::std::string::String>,
}
impl UpdateVirtualServiceInputBuilder {
    /// <p>The name of the virtual service to update.</p>
    /// This field is required.
    pub fn virtual_service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the virtual service to update.</p>
    pub fn set_virtual_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_service_name = input;
        self
    }
    /// <p>The name of the virtual service to update.</p>
    pub fn get_virtual_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_service_name
    }
    /// <p>The name of the service mesh that the virtual service resides in.</p>
    /// This field is required.
    pub fn mesh_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mesh_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service mesh that the virtual service resides in.</p>
    pub fn set_mesh_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mesh_name = input;
        self
    }
    /// <p>The name of the service mesh that the virtual service resides in.</p>
    pub fn get_mesh_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.mesh_name
    }
    /// <p>The new virtual service specification to apply. This overwrites the existing data.</p>
    /// This field is required.
    pub fn spec(mut self, input: crate::types::VirtualServiceSpec) -> Self {
        self.spec = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new virtual service specification to apply. This overwrites the existing data.</p>
    pub fn set_spec(mut self, input: ::std::option::Option<crate::types::VirtualServiceSpec>) -> Self {
        self.spec = input;
        self
    }
    /// <p>The new virtual service specification to apply. This overwrites the existing data.</p>
    pub fn get_spec(&self) -> &::std::option::Option<crate::types::VirtualServiceSpec> {
        &self.spec
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Up to 36 letters, numbers, hyphens, and underscores are allowed.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Up to 36 letters, numbers, hyphens, and underscores are allowed.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Up to 36 letters, numbers, hyphens, and underscores are allowed.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then it's the ID of the account that shared the mesh with your account. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub fn mesh_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mesh_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then it's the ID of the account that shared the mesh with your account. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub fn set_mesh_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mesh_owner = input;
        self
    }
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then it's the ID of the account that shared the mesh with your account. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub fn get_mesh_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.mesh_owner
    }
    /// Consumes the builder and constructs a [`UpdateVirtualServiceInput`](crate::operation::update_virtual_service::UpdateVirtualServiceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_virtual_service::UpdateVirtualServiceInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_virtual_service::UpdateVirtualServiceInput {
            virtual_service_name: self.virtual_service_name,
            mesh_name: self.mesh_name,
            spec: self.spec,
            client_token: self.client_token,
            mesh_owner: self.mesh_owner,
        })
    }
}
