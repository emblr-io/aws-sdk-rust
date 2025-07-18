// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteGatewayRouteInput {
    /// <p>The name of the gateway route to delete.</p>
    pub gateway_route_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the service mesh to delete the gateway route from.</p>
    pub mesh_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the virtual gateway to delete the route from.</p>
    pub virtual_gateway_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then it's the ID of the account that shared the mesh with your account. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub mesh_owner: ::std::option::Option<::std::string::String>,
}
impl DeleteGatewayRouteInput {
    /// <p>The name of the gateway route to delete.</p>
    pub fn gateway_route_name(&self) -> ::std::option::Option<&str> {
        self.gateway_route_name.as_deref()
    }
    /// <p>The name of the service mesh to delete the gateway route from.</p>
    pub fn mesh_name(&self) -> ::std::option::Option<&str> {
        self.mesh_name.as_deref()
    }
    /// <p>The name of the virtual gateway to delete the route from.</p>
    pub fn virtual_gateway_name(&self) -> ::std::option::Option<&str> {
        self.virtual_gateway_name.as_deref()
    }
    /// <p>The Amazon Web Services IAM account ID of the service mesh owner. If the account ID is not your own, then it's the ID of the account that shared the mesh with your account. For more information about mesh sharing, see <a href="https://docs.aws.amazon.com/app-mesh/latest/userguide/sharing.html">Working with shared meshes</a>.</p>
    pub fn mesh_owner(&self) -> ::std::option::Option<&str> {
        self.mesh_owner.as_deref()
    }
}
impl DeleteGatewayRouteInput {
    /// Creates a new builder-style object to manufacture [`DeleteGatewayRouteInput`](crate::operation::delete_gateway_route::DeleteGatewayRouteInput).
    pub fn builder() -> crate::operation::delete_gateway_route::builders::DeleteGatewayRouteInputBuilder {
        crate::operation::delete_gateway_route::builders::DeleteGatewayRouteInputBuilder::default()
    }
}

/// A builder for [`DeleteGatewayRouteInput`](crate::operation::delete_gateway_route::DeleteGatewayRouteInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteGatewayRouteInputBuilder {
    pub(crate) gateway_route_name: ::std::option::Option<::std::string::String>,
    pub(crate) mesh_name: ::std::option::Option<::std::string::String>,
    pub(crate) virtual_gateway_name: ::std::option::Option<::std::string::String>,
    pub(crate) mesh_owner: ::std::option::Option<::std::string::String>,
}
impl DeleteGatewayRouteInputBuilder {
    /// <p>The name of the gateway route to delete.</p>
    /// This field is required.
    pub fn gateway_route_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_route_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the gateway route to delete.</p>
    pub fn set_gateway_route_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_route_name = input;
        self
    }
    /// <p>The name of the gateway route to delete.</p>
    pub fn get_gateway_route_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_route_name
    }
    /// <p>The name of the service mesh to delete the gateway route from.</p>
    /// This field is required.
    pub fn mesh_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mesh_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service mesh to delete the gateway route from.</p>
    pub fn set_mesh_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mesh_name = input;
        self
    }
    /// <p>The name of the service mesh to delete the gateway route from.</p>
    pub fn get_mesh_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.mesh_name
    }
    /// <p>The name of the virtual gateway to delete the route from.</p>
    /// This field is required.
    pub fn virtual_gateway_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_gateway_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the virtual gateway to delete the route from.</p>
    pub fn set_virtual_gateway_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_gateway_name = input;
        self
    }
    /// <p>The name of the virtual gateway to delete the route from.</p>
    pub fn get_virtual_gateway_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_gateway_name
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
    /// Consumes the builder and constructs a [`DeleteGatewayRouteInput`](crate::operation::delete_gateway_route::DeleteGatewayRouteInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_gateway_route::DeleteGatewayRouteInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_gateway_route::DeleteGatewayRouteInput {
            gateway_route_name: self.gateway_route_name,
            mesh_name: self.mesh_name,
            virtual_gateway_name: self.virtual_gateway_name,
            mesh_owner: self.mesh_owner,
        })
    }
}
