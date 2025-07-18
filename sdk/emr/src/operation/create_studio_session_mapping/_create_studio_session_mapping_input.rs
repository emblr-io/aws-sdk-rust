// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateStudioSessionMappingInput {
    /// <p>The ID of the Amazon EMR Studio to which the user or group will be mapped.</p>
    pub studio_id: ::std::option::Option<::std::string::String>,
    /// <p>The globally unique identifier (GUID) of the user or group from the IAM Identity Center Identity Store. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub identity_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the user or group. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub identity_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the identity to map to the Amazon EMR Studio is a user or a group.</p>
    pub identity_type: ::std::option::Option<crate::types::IdentityType>,
    /// <p>The Amazon Resource Name (ARN) for the session policy that will be applied to the user or group. You should specify the ARN for the session policy that you want to apply, not the ARN of your user role. For more information, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio-user-role.html">Create an Amazon EMR Studio User Role with Session Policies</a>.</p>
    pub session_policy_arn: ::std::option::Option<::std::string::String>,
}
impl CreateStudioSessionMappingInput {
    /// <p>The ID of the Amazon EMR Studio to which the user or group will be mapped.</p>
    pub fn studio_id(&self) -> ::std::option::Option<&str> {
        self.studio_id.as_deref()
    }
    /// <p>The globally unique identifier (GUID) of the user or group from the IAM Identity Center Identity Store. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub fn identity_id(&self) -> ::std::option::Option<&str> {
        self.identity_id.as_deref()
    }
    /// <p>The name of the user or group. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub fn identity_name(&self) -> ::std::option::Option<&str> {
        self.identity_name.as_deref()
    }
    /// <p>Specifies whether the identity to map to the Amazon EMR Studio is a user or a group.</p>
    pub fn identity_type(&self) -> ::std::option::Option<&crate::types::IdentityType> {
        self.identity_type.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) for the session policy that will be applied to the user or group. You should specify the ARN for the session policy that you want to apply, not the ARN of your user role. For more information, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio-user-role.html">Create an Amazon EMR Studio User Role with Session Policies</a>.</p>
    pub fn session_policy_arn(&self) -> ::std::option::Option<&str> {
        self.session_policy_arn.as_deref()
    }
}
impl CreateStudioSessionMappingInput {
    /// Creates a new builder-style object to manufacture [`CreateStudioSessionMappingInput`](crate::operation::create_studio_session_mapping::CreateStudioSessionMappingInput).
    pub fn builder() -> crate::operation::create_studio_session_mapping::builders::CreateStudioSessionMappingInputBuilder {
        crate::operation::create_studio_session_mapping::builders::CreateStudioSessionMappingInputBuilder::default()
    }
}

/// A builder for [`CreateStudioSessionMappingInput`](crate::operation::create_studio_session_mapping::CreateStudioSessionMappingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateStudioSessionMappingInputBuilder {
    pub(crate) studio_id: ::std::option::Option<::std::string::String>,
    pub(crate) identity_id: ::std::option::Option<::std::string::String>,
    pub(crate) identity_name: ::std::option::Option<::std::string::String>,
    pub(crate) identity_type: ::std::option::Option<crate::types::IdentityType>,
    pub(crate) session_policy_arn: ::std::option::Option<::std::string::String>,
}
impl CreateStudioSessionMappingInputBuilder {
    /// <p>The ID of the Amazon EMR Studio to which the user or group will be mapped.</p>
    /// This field is required.
    pub fn studio_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.studio_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon EMR Studio to which the user or group will be mapped.</p>
    pub fn set_studio_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.studio_id = input;
        self
    }
    /// <p>The ID of the Amazon EMR Studio to which the user or group will be mapped.</p>
    pub fn get_studio_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.studio_id
    }
    /// <p>The globally unique identifier (GUID) of the user or group from the IAM Identity Center Identity Store. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub fn identity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The globally unique identifier (GUID) of the user or group from the IAM Identity Center Identity Store. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub fn set_identity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_id = input;
        self
    }
    /// <p>The globally unique identifier (GUID) of the user or group from the IAM Identity Center Identity Store. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserId">UserId</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-GroupId">GroupId</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub fn get_identity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_id
    }
    /// <p>The name of the user or group. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub fn identity_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the user or group. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub fn set_identity_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_name = input;
        self
    }
    /// <p>The name of the user or group. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_User.html#singlesignon-Type-User-UserName">UserName</a> and <a href="https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_Group.html#singlesignon-Type-Group-DisplayName">DisplayName</a> in the <i>IAM Identity Center Identity Store API Reference</i>. Either <code>IdentityName</code> or <code>IdentityId</code> must be specified, but not both.</p>
    pub fn get_identity_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_name
    }
    /// <p>Specifies whether the identity to map to the Amazon EMR Studio is a user or a group.</p>
    /// This field is required.
    pub fn identity_type(mut self, input: crate::types::IdentityType) -> Self {
        self.identity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the identity to map to the Amazon EMR Studio is a user or a group.</p>
    pub fn set_identity_type(mut self, input: ::std::option::Option<crate::types::IdentityType>) -> Self {
        self.identity_type = input;
        self
    }
    /// <p>Specifies whether the identity to map to the Amazon EMR Studio is a user or a group.</p>
    pub fn get_identity_type(&self) -> &::std::option::Option<crate::types::IdentityType> {
        &self.identity_type
    }
    /// <p>The Amazon Resource Name (ARN) for the session policy that will be applied to the user or group. You should specify the ARN for the session policy that you want to apply, not the ARN of your user role. For more information, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio-user-role.html">Create an Amazon EMR Studio User Role with Session Policies</a>.</p>
    /// This field is required.
    pub fn session_policy_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_policy_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the session policy that will be applied to the user or group. You should specify the ARN for the session policy that you want to apply, not the ARN of your user role. For more information, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio-user-role.html">Create an Amazon EMR Studio User Role with Session Policies</a>.</p>
    pub fn set_session_policy_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_policy_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the session policy that will be applied to the user or group. You should specify the ARN for the session policy that you want to apply, not the ARN of your user role. For more information, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-studio-user-role.html">Create an Amazon EMR Studio User Role with Session Policies</a>.</p>
    pub fn get_session_policy_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_policy_arn
    }
    /// Consumes the builder and constructs a [`CreateStudioSessionMappingInput`](crate::operation::create_studio_session_mapping::CreateStudioSessionMappingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_studio_session_mapping::CreateStudioSessionMappingInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_studio_session_mapping::CreateStudioSessionMappingInput {
            studio_id: self.studio_id,
            identity_id: self.identity_id,
            identity_name: self.identity_name,
            identity_type: self.identity_type,
            session_policy_arn: self.session_policy_arn,
        })
    }
}
