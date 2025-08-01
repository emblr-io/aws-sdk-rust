// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateActivationInput {
    /// <p>A user-defined description of the resource that you want to register with Systems Manager.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The name of the registered, managed node as it will appear in the Amazon Web Services Systems Manager console or when you use the Amazon Web Services command line tools to list Systems Manager resources.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub default_instance_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Identity and Access Management (IAM) role that you want to assign to the managed node. This IAM role must provide AssumeRole permissions for the Amazon Web Services Systems Manager service principal <code>ssm.amazonaws.com</code>. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/hybrid-multicloud-service-role.html">Create the IAM service role required for Systems Manager in a hybrid and multicloud environments</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p><note>
    /// <p>You can't specify an IAM service-linked role for this parameter. You must create a unique role.</p>
    /// </note>
    pub iam_role: ::std::option::Option<::std::string::String>,
    /// <p>Specify the maximum number of managed nodes you want to register. The default value is <code>1</code>.</p>
    pub registration_limit: ::std::option::Option<i32>,
    /// <p>The date by which this activation request should expire, in timestamp format, such as "2024-07-07T00:00:00". You can specify a date up to 30 days in advance. If you don't provide an expiration date, the activation code expires in 24 hours.</p>
    pub expiration_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag an activation to identify which servers or virtual machines (VMs) in your on-premises environment you intend to activate. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><important>
    /// <p>When you install SSM Agent on your on-premises servers and VMs, you specify an activation ID and code. When you specify the activation ID and code, tags assigned to the activation are automatically applied to the on-premises servers or VMs.</p>
    /// </important>
    /// <p>You can't add tags to or delete tags from an existing activation. You can tag your on-premises servers, edge devices, and VMs after they connect to Systems Manager for the first time and are assigned a managed node ID. This means they are listed in the Amazon Web Services Systems Manager console with an ID that is prefixed with "mi-". For information about how to add tags to your managed nodes, see <code>AddTagsToResource</code>. For information about how to remove tags from your managed nodes, see <code>RemoveTagsFromResource</code>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>Reserved for internal use.</p>
    pub registration_metadata: ::std::option::Option<::std::vec::Vec<crate::types::RegistrationMetadataItem>>,
}
impl CreateActivationInput {
    /// <p>A user-defined description of the resource that you want to register with Systems Manager.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The name of the registered, managed node as it will appear in the Amazon Web Services Systems Manager console or when you use the Amazon Web Services command line tools to list Systems Manager resources.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub fn default_instance_name(&self) -> ::std::option::Option<&str> {
        self.default_instance_name.as_deref()
    }
    /// <p>The name of the Identity and Access Management (IAM) role that you want to assign to the managed node. This IAM role must provide AssumeRole permissions for the Amazon Web Services Systems Manager service principal <code>ssm.amazonaws.com</code>. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/hybrid-multicloud-service-role.html">Create the IAM service role required for Systems Manager in a hybrid and multicloud environments</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p><note>
    /// <p>You can't specify an IAM service-linked role for this parameter. You must create a unique role.</p>
    /// </note>
    pub fn iam_role(&self) -> ::std::option::Option<&str> {
        self.iam_role.as_deref()
    }
    /// <p>Specify the maximum number of managed nodes you want to register. The default value is <code>1</code>.</p>
    pub fn registration_limit(&self) -> ::std::option::Option<i32> {
        self.registration_limit
    }
    /// <p>The date by which this activation request should expire, in timestamp format, such as "2024-07-07T00:00:00". You can specify a date up to 30 days in advance. If you don't provide an expiration date, the activation code expires in 24 hours.</p>
    pub fn expiration_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.expiration_date.as_ref()
    }
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag an activation to identify which servers or virtual machines (VMs) in your on-premises environment you intend to activate. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><important>
    /// <p>When you install SSM Agent on your on-premises servers and VMs, you specify an activation ID and code. When you specify the activation ID and code, tags assigned to the activation are automatically applied to the on-premises servers or VMs.</p>
    /// </important>
    /// <p>You can't add tags to or delete tags from an existing activation. You can tag your on-premises servers, edge devices, and VMs after they connect to Systems Manager for the first time and are assigned a managed node ID. This means they are listed in the Amazon Web Services Systems Manager console with an ID that is prefixed with "mi-". For information about how to add tags to your managed nodes, see <code>AddTagsToResource</code>. For information about how to remove tags from your managed nodes, see <code>RemoveTagsFromResource</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Reserved for internal use.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.registration_metadata.is_none()`.
    pub fn registration_metadata(&self) -> &[crate::types::RegistrationMetadataItem] {
        self.registration_metadata.as_deref().unwrap_or_default()
    }
}
impl CreateActivationInput {
    /// Creates a new builder-style object to manufacture [`CreateActivationInput`](crate::operation::create_activation::CreateActivationInput).
    pub fn builder() -> crate::operation::create_activation::builders::CreateActivationInputBuilder {
        crate::operation::create_activation::builders::CreateActivationInputBuilder::default()
    }
}

/// A builder for [`CreateActivationInput`](crate::operation::create_activation::CreateActivationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateActivationInputBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) default_instance_name: ::std::option::Option<::std::string::String>,
    pub(crate) iam_role: ::std::option::Option<::std::string::String>,
    pub(crate) registration_limit: ::std::option::Option<i32>,
    pub(crate) expiration_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) registration_metadata: ::std::option::Option<::std::vec::Vec<crate::types::RegistrationMetadataItem>>,
}
impl CreateActivationInputBuilder {
    /// <p>A user-defined description of the resource that you want to register with Systems Manager.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A user-defined description of the resource that you want to register with Systems Manager.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A user-defined description of the resource that you want to register with Systems Manager.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The name of the registered, managed node as it will appear in the Amazon Web Services Systems Manager console or when you use the Amazon Web Services command line tools to list Systems Manager resources.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub fn default_instance_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_instance_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the registered, managed node as it will appear in the Amazon Web Services Systems Manager console or when you use the Amazon Web Services command line tools to list Systems Manager resources.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub fn set_default_instance_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_instance_name = input;
        self
    }
    /// <p>The name of the registered, managed node as it will appear in the Amazon Web Services Systems Manager console or when you use the Amazon Web Services command line tools to list Systems Manager resources.</p><important>
    /// <p>Don't enter personally identifiable information in this field.</p>
    /// </important>
    pub fn get_default_instance_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_instance_name
    }
    /// <p>The name of the Identity and Access Management (IAM) role that you want to assign to the managed node. This IAM role must provide AssumeRole permissions for the Amazon Web Services Systems Manager service principal <code>ssm.amazonaws.com</code>. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/hybrid-multicloud-service-role.html">Create the IAM service role required for Systems Manager in a hybrid and multicloud environments</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p><note>
    /// <p>You can't specify an IAM service-linked role for this parameter. You must create a unique role.</p>
    /// </note>
    /// This field is required.
    pub fn iam_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.iam_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Identity and Access Management (IAM) role that you want to assign to the managed node. This IAM role must provide AssumeRole permissions for the Amazon Web Services Systems Manager service principal <code>ssm.amazonaws.com</code>. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/hybrid-multicloud-service-role.html">Create the IAM service role required for Systems Manager in a hybrid and multicloud environments</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p><note>
    /// <p>You can't specify an IAM service-linked role for this parameter. You must create a unique role.</p>
    /// </note>
    pub fn set_iam_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.iam_role = input;
        self
    }
    /// <p>The name of the Identity and Access Management (IAM) role that you want to assign to the managed node. This IAM role must provide AssumeRole permissions for the Amazon Web Services Systems Manager service principal <code>ssm.amazonaws.com</code>. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/hybrid-multicloud-service-role.html">Create the IAM service role required for Systems Manager in a hybrid and multicloud environments</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p><note>
    /// <p>You can't specify an IAM service-linked role for this parameter. You must create a unique role.</p>
    /// </note>
    pub fn get_iam_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.iam_role
    }
    /// <p>Specify the maximum number of managed nodes you want to register. The default value is <code>1</code>.</p>
    pub fn registration_limit(mut self, input: i32) -> Self {
        self.registration_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify the maximum number of managed nodes you want to register. The default value is <code>1</code>.</p>
    pub fn set_registration_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.registration_limit = input;
        self
    }
    /// <p>Specify the maximum number of managed nodes you want to register. The default value is <code>1</code>.</p>
    pub fn get_registration_limit(&self) -> &::std::option::Option<i32> {
        &self.registration_limit
    }
    /// <p>The date by which this activation request should expire, in timestamp format, such as "2024-07-07T00:00:00". You can specify a date up to 30 days in advance. If you don't provide an expiration date, the activation code expires in 24 hours.</p>
    pub fn expiration_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.expiration_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date by which this activation request should expire, in timestamp format, such as "2024-07-07T00:00:00". You can specify a date up to 30 days in advance. If you don't provide an expiration date, the activation code expires in 24 hours.</p>
    pub fn set_expiration_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.expiration_date = input;
        self
    }
    /// <p>The date by which this activation request should expire, in timestamp format, such as "2024-07-07T00:00:00". You can specify a date up to 30 days in advance. If you don't provide an expiration date, the activation code expires in 24 hours.</p>
    pub fn get_expiration_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.expiration_date
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag an activation to identify which servers or virtual machines (VMs) in your on-premises environment you intend to activate. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><important>
    /// <p>When you install SSM Agent on your on-premises servers and VMs, you specify an activation ID and code. When you specify the activation ID and code, tags assigned to the activation are automatically applied to the on-premises servers or VMs.</p>
    /// </important>
    /// <p>You can't add tags to or delete tags from an existing activation. You can tag your on-premises servers, edge devices, and VMs after they connect to Systems Manager for the first time and are assigned a managed node ID. This means they are listed in the Amazon Web Services Systems Manager console with an ID that is prefixed with "mi-". For information about how to add tags to your managed nodes, see <code>AddTagsToResource</code>. For information about how to remove tags from your managed nodes, see <code>RemoveTagsFromResource</code>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag an activation to identify which servers or virtual machines (VMs) in your on-premises environment you intend to activate. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><important>
    /// <p>When you install SSM Agent on your on-premises servers and VMs, you specify an activation ID and code. When you specify the activation ID and code, tags assigned to the activation are automatically applied to the on-premises servers or VMs.</p>
    /// </important>
    /// <p>You can't add tags to or delete tags from an existing activation. You can tag your on-premises servers, edge devices, and VMs after they connect to Systems Manager for the first time and are assigned a managed node ID. This means they are listed in the Amazon Web Services Systems Manager console with an ID that is prefixed with "mi-". For information about how to add tags to your managed nodes, see <code>AddTagsToResource</code>. For information about how to remove tags from your managed nodes, see <code>RemoveTagsFromResource</code>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Optional metadata that you assign to a resource. Tags enable you to categorize a resource in different ways, such as by purpose, owner, or environment. For example, you might want to tag an activation to identify which servers or virtual machines (VMs) in your on-premises environment you intend to activate. In this case, you could specify the following key-value pairs:</p>
    /// <ul>
    /// <li>
    /// <p><code>Key=OS,Value=Windows</code></p></li>
    /// <li>
    /// <p><code>Key=Environment,Value=Production</code></p></li>
    /// </ul><important>
    /// <p>When you install SSM Agent on your on-premises servers and VMs, you specify an activation ID and code. When you specify the activation ID and code, tags assigned to the activation are automatically applied to the on-premises servers or VMs.</p>
    /// </important>
    /// <p>You can't add tags to or delete tags from an existing activation. You can tag your on-premises servers, edge devices, and VMs after they connect to Systems Manager for the first time and are assigned a managed node ID. This means they are listed in the Amazon Web Services Systems Manager console with an ID that is prefixed with "mi-". For information about how to add tags to your managed nodes, see <code>AddTagsToResource</code>. For information about how to remove tags from your managed nodes, see <code>RemoveTagsFromResource</code>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Appends an item to `registration_metadata`.
    ///
    /// To override the contents of this collection use [`set_registration_metadata`](Self::set_registration_metadata).
    ///
    /// <p>Reserved for internal use.</p>
    pub fn registration_metadata(mut self, input: crate::types::RegistrationMetadataItem) -> Self {
        let mut v = self.registration_metadata.unwrap_or_default();
        v.push(input);
        self.registration_metadata = ::std::option::Option::Some(v);
        self
    }
    /// <p>Reserved for internal use.</p>
    pub fn set_registration_metadata(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RegistrationMetadataItem>>) -> Self {
        self.registration_metadata = input;
        self
    }
    /// <p>Reserved for internal use.</p>
    pub fn get_registration_metadata(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RegistrationMetadataItem>> {
        &self.registration_metadata
    }
    /// Consumes the builder and constructs a [`CreateActivationInput`](crate::operation::create_activation::CreateActivationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_activation::CreateActivationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_activation::CreateActivationInput {
            description: self.description,
            default_instance_name: self.default_instance_name,
            iam_role: self.iam_role,
            registration_limit: self.registration_limit,
            expiration_date: self.expiration_date,
            tags: self.tags,
            registration_metadata: self.registration_metadata,
        })
    }
}
