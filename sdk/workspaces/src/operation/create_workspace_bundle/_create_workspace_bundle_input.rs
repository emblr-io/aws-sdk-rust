// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateWorkspaceBundleInput {
    /// <p>The name of the bundle.</p>
    pub bundle_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the bundle.</p>
    pub bundle_description: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the image that is used to create the bundle.</p>
    pub image_id: ::std::option::Option<::std::string::String>,
    /// <p>Describes the compute type of the bundle.</p>
    pub compute_type: ::std::option::Option<crate::types::ComputeType>,
    /// <p>Describes the user volume for a WorkSpace bundle.</p>
    pub user_storage: ::std::option::Option<crate::types::UserStorage>,
    /// <p>Describes the root volume for a WorkSpace bundle.</p>
    pub root_storage: ::std::option::Option<crate::types::RootStorage>,
    /// <p>The tags associated with the bundle.</p><note>
    /// <p>To add tags at the same time when you're creating the bundle, you must create an IAM policy that grants your IAM user permissions to use <code>workspaces:CreateTags</code>.</p>
    /// </note>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateWorkspaceBundleInput {
    /// <p>The name of the bundle.</p>
    pub fn bundle_name(&self) -> ::std::option::Option<&str> {
        self.bundle_name.as_deref()
    }
    /// <p>The description of the bundle.</p>
    pub fn bundle_description(&self) -> ::std::option::Option<&str> {
        self.bundle_description.as_deref()
    }
    /// <p>The identifier of the image that is used to create the bundle.</p>
    pub fn image_id(&self) -> ::std::option::Option<&str> {
        self.image_id.as_deref()
    }
    /// <p>Describes the compute type of the bundle.</p>
    pub fn compute_type(&self) -> ::std::option::Option<&crate::types::ComputeType> {
        self.compute_type.as_ref()
    }
    /// <p>Describes the user volume for a WorkSpace bundle.</p>
    pub fn user_storage(&self) -> ::std::option::Option<&crate::types::UserStorage> {
        self.user_storage.as_ref()
    }
    /// <p>Describes the root volume for a WorkSpace bundle.</p>
    pub fn root_storage(&self) -> ::std::option::Option<&crate::types::RootStorage> {
        self.root_storage.as_ref()
    }
    /// <p>The tags associated with the bundle.</p><note>
    /// <p>To add tags at the same time when you're creating the bundle, you must create an IAM policy that grants your IAM user permissions to use <code>workspaces:CreateTags</code>.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateWorkspaceBundleInput {
    /// Creates a new builder-style object to manufacture [`CreateWorkspaceBundleInput`](crate::operation::create_workspace_bundle::CreateWorkspaceBundleInput).
    pub fn builder() -> crate::operation::create_workspace_bundle::builders::CreateWorkspaceBundleInputBuilder {
        crate::operation::create_workspace_bundle::builders::CreateWorkspaceBundleInputBuilder::default()
    }
}

/// A builder for [`CreateWorkspaceBundleInput`](crate::operation::create_workspace_bundle::CreateWorkspaceBundleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateWorkspaceBundleInputBuilder {
    pub(crate) bundle_name: ::std::option::Option<::std::string::String>,
    pub(crate) bundle_description: ::std::option::Option<::std::string::String>,
    pub(crate) image_id: ::std::option::Option<::std::string::String>,
    pub(crate) compute_type: ::std::option::Option<crate::types::ComputeType>,
    pub(crate) user_storage: ::std::option::Option<crate::types::UserStorage>,
    pub(crate) root_storage: ::std::option::Option<crate::types::RootStorage>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateWorkspaceBundleInputBuilder {
    /// <p>The name of the bundle.</p>
    /// This field is required.
    pub fn bundle_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bundle_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the bundle.</p>
    pub fn set_bundle_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bundle_name = input;
        self
    }
    /// <p>The name of the bundle.</p>
    pub fn get_bundle_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bundle_name
    }
    /// <p>The description of the bundle.</p>
    /// This field is required.
    pub fn bundle_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bundle_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the bundle.</p>
    pub fn set_bundle_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bundle_description = input;
        self
    }
    /// <p>The description of the bundle.</p>
    pub fn get_bundle_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.bundle_description
    }
    /// <p>The identifier of the image that is used to create the bundle.</p>
    /// This field is required.
    pub fn image_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the image that is used to create the bundle.</p>
    pub fn set_image_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_id = input;
        self
    }
    /// <p>The identifier of the image that is used to create the bundle.</p>
    pub fn get_image_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_id
    }
    /// <p>Describes the compute type of the bundle.</p>
    /// This field is required.
    pub fn compute_type(mut self, input: crate::types::ComputeType) -> Self {
        self.compute_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the compute type of the bundle.</p>
    pub fn set_compute_type(mut self, input: ::std::option::Option<crate::types::ComputeType>) -> Self {
        self.compute_type = input;
        self
    }
    /// <p>Describes the compute type of the bundle.</p>
    pub fn get_compute_type(&self) -> &::std::option::Option<crate::types::ComputeType> {
        &self.compute_type
    }
    /// <p>Describes the user volume for a WorkSpace bundle.</p>
    /// This field is required.
    pub fn user_storage(mut self, input: crate::types::UserStorage) -> Self {
        self.user_storage = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the user volume for a WorkSpace bundle.</p>
    pub fn set_user_storage(mut self, input: ::std::option::Option<crate::types::UserStorage>) -> Self {
        self.user_storage = input;
        self
    }
    /// <p>Describes the user volume for a WorkSpace bundle.</p>
    pub fn get_user_storage(&self) -> &::std::option::Option<crate::types::UserStorage> {
        &self.user_storage
    }
    /// <p>Describes the root volume for a WorkSpace bundle.</p>
    pub fn root_storage(mut self, input: crate::types::RootStorage) -> Self {
        self.root_storage = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the root volume for a WorkSpace bundle.</p>
    pub fn set_root_storage(mut self, input: ::std::option::Option<crate::types::RootStorage>) -> Self {
        self.root_storage = input;
        self
    }
    /// <p>Describes the root volume for a WorkSpace bundle.</p>
    pub fn get_root_storage(&self) -> &::std::option::Option<crate::types::RootStorage> {
        &self.root_storage
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags associated with the bundle.</p><note>
    /// <p>To add tags at the same time when you're creating the bundle, you must create an IAM policy that grants your IAM user permissions to use <code>workspaces:CreateTags</code>.</p>
    /// </note>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags associated with the bundle.</p><note>
    /// <p>To add tags at the same time when you're creating the bundle, you must create an IAM policy that grants your IAM user permissions to use <code>workspaces:CreateTags</code>.</p>
    /// </note>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags associated with the bundle.</p><note>
    /// <p>To add tags at the same time when you're creating the bundle, you must create an IAM policy that grants your IAM user permissions to use <code>workspaces:CreateTags</code>.</p>
    /// </note>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateWorkspaceBundleInput`](crate::operation::create_workspace_bundle::CreateWorkspaceBundleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_workspace_bundle::CreateWorkspaceBundleInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_workspace_bundle::CreateWorkspaceBundleInput {
            bundle_name: self.bundle_name,
            bundle_description: self.bundle_description,
            image_id: self.image_id,
            compute_type: self.compute_type,
            user_storage: self.user_storage,
            root_storage: self.root_storage,
            tags: self.tags,
        })
    }
}
