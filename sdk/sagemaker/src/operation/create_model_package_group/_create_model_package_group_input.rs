// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateModelPackageGroupInput {
    /// <p>The name of the model group.</p>
    pub model_package_group_name: ::std::option::Option<::std::string::String>,
    /// <p>A description for the model group.</p>
    pub model_package_group_description: ::std::option::Option<::std::string::String>,
    /// <p>A list of key value pairs associated with the model group. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateModelPackageGroupInput {
    /// <p>The name of the model group.</p>
    pub fn model_package_group_name(&self) -> ::std::option::Option<&str> {
        self.model_package_group_name.as_deref()
    }
    /// <p>A description for the model group.</p>
    pub fn model_package_group_description(&self) -> ::std::option::Option<&str> {
        self.model_package_group_description.as_deref()
    }
    /// <p>A list of key value pairs associated with the model group. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateModelPackageGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateModelPackageGroupInput`](crate::operation::create_model_package_group::CreateModelPackageGroupInput).
    pub fn builder() -> crate::operation::create_model_package_group::builders::CreateModelPackageGroupInputBuilder {
        crate::operation::create_model_package_group::builders::CreateModelPackageGroupInputBuilder::default()
    }
}

/// A builder for [`CreateModelPackageGroupInput`](crate::operation::create_model_package_group::CreateModelPackageGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateModelPackageGroupInputBuilder {
    pub(crate) model_package_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) model_package_group_description: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateModelPackageGroupInputBuilder {
    /// <p>The name of the model group.</p>
    /// This field is required.
    pub fn model_package_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_package_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the model group.</p>
    pub fn set_model_package_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_package_group_name = input;
        self
    }
    /// <p>The name of the model group.</p>
    pub fn get_model_package_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_package_group_name
    }
    /// <p>A description for the model group.</p>
    pub fn model_package_group_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_package_group_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the model group.</p>
    pub fn set_model_package_group_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_package_group_description = input;
        self
    }
    /// <p>A description for the model group.</p>
    pub fn get_model_package_group_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_package_group_description
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of key value pairs associated with the model group. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of key value pairs associated with the model group. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of key value pairs associated with the model group. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateModelPackageGroupInput`](crate::operation::create_model_package_group::CreateModelPackageGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_model_package_group::CreateModelPackageGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_model_package_group::CreateModelPackageGroupInput {
            model_package_group_name: self.model_package_group_name,
            model_package_group_description: self.model_package_group_description,
            tags: self.tags,
        })
    }
}
