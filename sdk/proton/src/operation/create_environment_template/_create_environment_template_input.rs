// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateEnvironmentTemplateInput {
    /// <p>The name of the environment template.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The environment template name as displayed in the developer interface.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the environment template.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A customer provided encryption key that Proton uses to encrypt data.</p>
    pub encryption_key: ::std::option::Option<::std::string::String>,
    /// <p>When included, indicates that the environment template is for customer provisioned and managed infrastructure.</p>
    pub provisioning: ::std::option::Option<crate::types::Provisioning>,
    /// <p>An optional list of metadata items that you can associate with the Proton environment template. A tag is a key-value pair.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/resources.html">Proton resources and tagging</a> in the <i>Proton User Guide</i>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateEnvironmentTemplateInput {
    /// <p>The name of the environment template.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The environment template name as displayed in the developer interface.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>A description of the environment template.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A customer provided encryption key that Proton uses to encrypt data.</p>
    pub fn encryption_key(&self) -> ::std::option::Option<&str> {
        self.encryption_key.as_deref()
    }
    /// <p>When included, indicates that the environment template is for customer provisioned and managed infrastructure.</p>
    pub fn provisioning(&self) -> ::std::option::Option<&crate::types::Provisioning> {
        self.provisioning.as_ref()
    }
    /// <p>An optional list of metadata items that you can associate with the Proton environment template. A tag is a key-value pair.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/resources.html">Proton resources and tagging</a> in the <i>Proton User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for CreateEnvironmentTemplateInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateEnvironmentTemplateInput");
        formatter.field("name", &self.name);
        formatter.field("display_name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("encryption_key", &self.encryption_key);
        formatter.field("provisioning", &self.provisioning);
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
impl CreateEnvironmentTemplateInput {
    /// Creates a new builder-style object to manufacture [`CreateEnvironmentTemplateInput`](crate::operation::create_environment_template::CreateEnvironmentTemplateInput).
    pub fn builder() -> crate::operation::create_environment_template::builders::CreateEnvironmentTemplateInputBuilder {
        crate::operation::create_environment_template::builders::CreateEnvironmentTemplateInputBuilder::default()
    }
}

/// A builder for [`CreateEnvironmentTemplateInput`](crate::operation::create_environment_template::CreateEnvironmentTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateEnvironmentTemplateInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) encryption_key: ::std::option::Option<::std::string::String>,
    pub(crate) provisioning: ::std::option::Option<crate::types::Provisioning>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateEnvironmentTemplateInputBuilder {
    /// <p>The name of the environment template.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the environment template.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the environment template.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The environment template name as displayed in the developer interface.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The environment template name as displayed in the developer interface.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The environment template name as displayed in the developer interface.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>A description of the environment template.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the environment template.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the environment template.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A customer provided encryption key that Proton uses to encrypt data.</p>
    pub fn encryption_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.encryption_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A customer provided encryption key that Proton uses to encrypt data.</p>
    pub fn set_encryption_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.encryption_key = input;
        self
    }
    /// <p>A customer provided encryption key that Proton uses to encrypt data.</p>
    pub fn get_encryption_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.encryption_key
    }
    /// <p>When included, indicates that the environment template is for customer provisioned and managed infrastructure.</p>
    pub fn provisioning(mut self, input: crate::types::Provisioning) -> Self {
        self.provisioning = ::std::option::Option::Some(input);
        self
    }
    /// <p>When included, indicates that the environment template is for customer provisioned and managed infrastructure.</p>
    pub fn set_provisioning(mut self, input: ::std::option::Option<crate::types::Provisioning>) -> Self {
        self.provisioning = input;
        self
    }
    /// <p>When included, indicates that the environment template is for customer provisioned and managed infrastructure.</p>
    pub fn get_provisioning(&self) -> &::std::option::Option<crate::types::Provisioning> {
        &self.provisioning
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An optional list of metadata items that you can associate with the Proton environment template. A tag is a key-value pair.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/resources.html">Proton resources and tagging</a> in the <i>Proton User Guide</i>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>An optional list of metadata items that you can associate with the Proton environment template. A tag is a key-value pair.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/resources.html">Proton resources and tagging</a> in the <i>Proton User Guide</i>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An optional list of metadata items that you can associate with the Proton environment template. A tag is a key-value pair.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/proton/latest/userguide/resources.html">Proton resources and tagging</a> in the <i>Proton User Guide</i>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateEnvironmentTemplateInput`](crate::operation::create_environment_template::CreateEnvironmentTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_environment_template::CreateEnvironmentTemplateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_environment_template::CreateEnvironmentTemplateInput {
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            encryption_key: self.encryption_key,
            provisioning: self.provisioning,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for CreateEnvironmentTemplateInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateEnvironmentTemplateInputBuilder");
        formatter.field("name", &self.name);
        formatter.field("display_name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("encryption_key", &self.encryption_key);
        formatter.field("provisioning", &self.provisioning);
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
