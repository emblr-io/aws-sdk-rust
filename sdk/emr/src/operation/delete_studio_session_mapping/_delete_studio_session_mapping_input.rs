// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteStudioSessionMappingInput {
    /// <p>The ID of the Amazon EMR Studio.</p>
    pub studio_id: ::std::option::Option<::std::string::String>,
    /// <p>The globally unique identifier (GUID) of the user or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub identity_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the user name or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub identity_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the identity to delete from the Amazon EMR Studio is a user or a group.</p>
    pub identity_type: ::std::option::Option<crate::types::IdentityType>,
}
impl DeleteStudioSessionMappingInput {
    /// <p>The ID of the Amazon EMR Studio.</p>
    pub fn studio_id(&self) -> ::std::option::Option<&str> {
        self.studio_id.as_deref()
    }
    /// <p>The globally unique identifier (GUID) of the user or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub fn identity_id(&self) -> ::std::option::Option<&str> {
        self.identity_id.as_deref()
    }
    /// <p>The name of the user name or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub fn identity_name(&self) -> ::std::option::Option<&str> {
        self.identity_name.as_deref()
    }
    /// <p>Specifies whether the identity to delete from the Amazon EMR Studio is a user or a group.</p>
    pub fn identity_type(&self) -> ::std::option::Option<&crate::types::IdentityType> {
        self.identity_type.as_ref()
    }
}
impl DeleteStudioSessionMappingInput {
    /// Creates a new builder-style object to manufacture [`DeleteStudioSessionMappingInput`](crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingInput).
    pub fn builder() -> crate::operation::delete_studio_session_mapping::builders::DeleteStudioSessionMappingInputBuilder {
        crate::operation::delete_studio_session_mapping::builders::DeleteStudioSessionMappingInputBuilder::default()
    }
}

/// A builder for [`DeleteStudioSessionMappingInput`](crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteStudioSessionMappingInputBuilder {
    pub(crate) studio_id: ::std::option::Option<::std::string::String>,
    pub(crate) identity_id: ::std::option::Option<::std::string::String>,
    pub(crate) identity_name: ::std::option::Option<::std::string::String>,
    pub(crate) identity_type: ::std::option::Option<crate::types::IdentityType>,
}
impl DeleteStudioSessionMappingInputBuilder {
    /// <p>The ID of the Amazon EMR Studio.</p>
    /// This field is required.
    pub fn studio_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.studio_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon EMR Studio.</p>
    pub fn set_studio_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.studio_id = input;
        self
    }
    /// <p>The ID of the Amazon EMR Studio.</p>
    pub fn get_studio_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.studio_id
    }
    /// <p>The globally unique identifier (GUID) of the user or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub fn identity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The globally unique identifier (GUID) of the user or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub fn set_identity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_id = input;
        self
    }
    /// <p>The globally unique identifier (GUID) of the user or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub fn get_identity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_id
    }
    /// <p>The name of the user name or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub fn identity_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the user name or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub fn set_identity_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_name = input;
        self
    }
    /// <p>The name of the user name or group to remove from the Amazon EMR Studio. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified.</p>
    pub fn get_identity_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_name
    }
    /// <p>Specifies whether the identity to delete from the Amazon EMR Studio is a user or a group.</p>
    /// This field is required.
    pub fn identity_type(mut self, input: crate::types::IdentityType) -> Self {
        self.identity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the identity to delete from the Amazon EMR Studio is a user or a group.</p>
    pub fn set_identity_type(mut self, input: ::std::option::Option<crate::types::IdentityType>) -> Self {
        self.identity_type = input;
        self
    }
    /// <p>Specifies whether the identity to delete from the Amazon EMR Studio is a user or a group.</p>
    pub fn get_identity_type(&self) -> &::std::option::Option<crate::types::IdentityType> {
        &self.identity_type
    }
    /// Consumes the builder and constructs a [`DeleteStudioSessionMappingInput`](crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingInput {
            studio_id: self.studio_id,
            identity_id: self.identity_id,
            identity_name: self.identity_name,
            identity_type: self.identity_type,
        })
    }
}
