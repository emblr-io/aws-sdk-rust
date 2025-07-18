// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMeshInput {
    /// <p>The name of the service mesh to delete.</p>
    pub mesh_name: ::std::option::Option<::std::string::String>,
}
impl DeleteMeshInput {
    /// <p>The name of the service mesh to delete.</p>
    pub fn mesh_name(&self) -> ::std::option::Option<&str> {
        self.mesh_name.as_deref()
    }
}
impl DeleteMeshInput {
    /// Creates a new builder-style object to manufacture [`DeleteMeshInput`](crate::operation::delete_mesh::DeleteMeshInput).
    pub fn builder() -> crate::operation::delete_mesh::builders::DeleteMeshInputBuilder {
        crate::operation::delete_mesh::builders::DeleteMeshInputBuilder::default()
    }
}

/// A builder for [`DeleteMeshInput`](crate::operation::delete_mesh::DeleteMeshInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteMeshInputBuilder {
    pub(crate) mesh_name: ::std::option::Option<::std::string::String>,
}
impl DeleteMeshInputBuilder {
    /// <p>The name of the service mesh to delete.</p>
    /// This field is required.
    pub fn mesh_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mesh_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service mesh to delete.</p>
    pub fn set_mesh_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mesh_name = input;
        self
    }
    /// <p>The name of the service mesh to delete.</p>
    pub fn get_mesh_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.mesh_name
    }
    /// Consumes the builder and constructs a [`DeleteMeshInput`](crate::operation::delete_mesh::DeleteMeshInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_mesh::DeleteMeshInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_mesh::DeleteMeshInput { mesh_name: self.mesh_name })
    }
}
