// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteSceneInput {
    /// <p>The ID of the workspace.</p>
    pub workspace_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the scene to delete.</p>
    pub scene_id: ::std::option::Option<::std::string::String>,
}
impl DeleteSceneInput {
    /// <p>The ID of the workspace.</p>
    pub fn workspace_id(&self) -> ::std::option::Option<&str> {
        self.workspace_id.as_deref()
    }
    /// <p>The ID of the scene to delete.</p>
    pub fn scene_id(&self) -> ::std::option::Option<&str> {
        self.scene_id.as_deref()
    }
}
impl DeleteSceneInput {
    /// Creates a new builder-style object to manufacture [`DeleteSceneInput`](crate::operation::delete_scene::DeleteSceneInput).
    pub fn builder() -> crate::operation::delete_scene::builders::DeleteSceneInputBuilder {
        crate::operation::delete_scene::builders::DeleteSceneInputBuilder::default()
    }
}

/// A builder for [`DeleteSceneInput`](crate::operation::delete_scene::DeleteSceneInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteSceneInputBuilder {
    pub(crate) workspace_id: ::std::option::Option<::std::string::String>,
    pub(crate) scene_id: ::std::option::Option<::std::string::String>,
}
impl DeleteSceneInputBuilder {
    /// <p>The ID of the workspace.</p>
    /// This field is required.
    pub fn workspace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workspace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the workspace.</p>
    pub fn set_workspace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workspace_id = input;
        self
    }
    /// <p>The ID of the workspace.</p>
    pub fn get_workspace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workspace_id
    }
    /// <p>The ID of the scene to delete.</p>
    /// This field is required.
    pub fn scene_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scene_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the scene to delete.</p>
    pub fn set_scene_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scene_id = input;
        self
    }
    /// <p>The ID of the scene to delete.</p>
    pub fn get_scene_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.scene_id
    }
    /// Consumes the builder and constructs a [`DeleteSceneInput`](crate::operation::delete_scene::DeleteSceneInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_scene::DeleteSceneInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_scene::DeleteSceneInput {
            workspace_id: self.workspace_id,
            scene_id: self.scene_id,
        })
    }
}
