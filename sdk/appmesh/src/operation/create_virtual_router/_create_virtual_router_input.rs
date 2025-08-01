// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateVirtualRouterInput {
    /// <p>The name to use for the virtual router.</p>
    pub virtual_router_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the service mesh to create the virtual router in.</p>
    pub mesh_name: ::std::option::Option<::std::string::String>,
    /// <p>The virtual router specification to apply.</p>
    pub spec: ::std::option::Option<crate::types::VirtualRouterSpec>,
    /// <p>Optional metadata that you can apply to the virtual router to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::TagRef>>,
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Up to 36 letters, numbers, hyphens, and underscores are allowed.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then the account that you specify must share the mesh with your account before you can create the resource in the service mesh. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub mesh_owner: ::std::option::Option<::std::string::String>,
}
impl CreateVirtualRouterInput {
    /// <p>The name to use for the virtual router.</p>
    pub fn virtual_router_name(&self) -> ::std::option::Option<&str> {
        self.virtual_router_name.as_deref()
    }
    /// <p>The name of the service mesh to create the virtual router in.</p>
    pub fn mesh_name(&self) -> ::std::option::Option<&str> {
        self.mesh_name.as_deref()
    }
    /// <p>The virtual router specification to apply.</p>
    pub fn spec(&self) -> ::std::option::Option<&crate::types::VirtualRouterSpec> {
        self.spec.as_ref()
    }
    /// <p>Optional metadata that you can apply to the virtual router to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::TagRef] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Up to 36 letters, numbers, hyphens, and underscores are allowed.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then the account that you specify must share the mesh with your account before you can create the resource in the service mesh. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub fn mesh_owner(&self) -> ::std::option::Option<&str> {
        self.mesh_owner.as_deref()
    }
}
impl CreateVirtualRouterInput {
    /// Creates a new builder-style object to manufacture [`CreateVirtualRouterInput`](crate::operation::create_virtual_router::CreateVirtualRouterInput).
    pub fn builder() -> crate::operation::create_virtual_router::builders::CreateVirtualRouterInputBuilder {
        crate::operation::create_virtual_router::builders::CreateVirtualRouterInputBuilder::default()
    }
}

/// A builder for [`CreateVirtualRouterInput`](crate::operation::create_virtual_router::CreateVirtualRouterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateVirtualRouterInputBuilder {
    pub(crate) virtual_router_name: ::std::option::Option<::std::string::String>,
    pub(crate) mesh_name: ::std::option::Option<::std::string::String>,
    pub(crate) spec: ::std::option::Option<crate::types::VirtualRouterSpec>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::TagRef>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) mesh_owner: ::std::option::Option<::std::string::String>,
}
impl CreateVirtualRouterInputBuilder {
    /// <p>The name to use for the virtual router.</p>
    /// This field is required.
    pub fn virtual_router_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_router_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name to use for the virtual router.</p>
    pub fn set_virtual_router_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_router_name = input;
        self
    }
    /// <p>The name to use for the virtual router.</p>
    pub fn get_virtual_router_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_router_name
    }
    /// <p>The name of the service mesh to create the virtual router in.</p>
    /// This field is required.
    pub fn mesh_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mesh_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service mesh to create the virtual router in.</p>
    pub fn set_mesh_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mesh_name = input;
        self
    }
    /// <p>The name of the service mesh to create the virtual router in.</p>
    pub fn get_mesh_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.mesh_name
    }
    /// <p>The virtual router specification to apply.</p>
    /// This field is required.
    pub fn spec(mut self, input: crate::types::VirtualRouterSpec) -> Self {
        self.spec = ::std::option::Option::Some(input);
        self
    }
    /// <p>The virtual router specification to apply.</p>
    pub fn set_spec(mut self, input: ::std::option::Option<crate::types::VirtualRouterSpec>) -> Self {
        self.spec = input;
        self
    }
    /// <p>The virtual router specification to apply.</p>
    pub fn get_spec(&self) -> &::std::option::Option<crate::types::VirtualRouterSpec> {
        &self.spec
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Optional metadata that you can apply to the virtual router to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    pub fn tags(mut self, input: crate::types::TagRef) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Optional metadata that you can apply to the virtual router to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TagRef>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Optional metadata that you can apply to the virtual router to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Tag keys can have a maximum character length of 128 characters, and tag values can have a maximum length of 256 characters.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TagRef>> {
        &self.tags
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
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then the account that you specify must share the mesh with your account before you can create the resource in the service mesh. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub fn mesh_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mesh_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then the account that you specify must share the mesh with your account before you can create the resource in the service mesh. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub fn set_mesh_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mesh_owner = input;
        self
    }
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then the account that you specify must share the mesh with your account before you can create the resource in the service mesh. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub fn get_mesh_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.mesh_owner
    }
    /// Consumes the builder and constructs a [`CreateVirtualRouterInput`](crate::operation::create_virtual_router::CreateVirtualRouterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_virtual_router::CreateVirtualRouterInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_virtual_router::CreateVirtualRouterInput {
            virtual_router_name: self.virtual_router_name,
            mesh_name: self.mesh_name,
            spec: self.spec,
            tags: self.tags,
            client_token: self.client_token,
            mesh_owner: self.mesh_owner,
        })
    }
}
