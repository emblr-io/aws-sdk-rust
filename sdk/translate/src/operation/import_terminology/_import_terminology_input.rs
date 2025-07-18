// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportTerminologyInput {
    /// <p>The name of the custom terminology being imported.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The merge strategy of the custom terminology being imported. Currently, only the OVERWRITE merge strategy is supported. In this case, the imported terminology will overwrite an existing terminology of the same name.</p>
    pub merge_strategy: ::std::option::Option<crate::types::MergeStrategy>,
    /// <p>The description of the custom terminology being imported.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The terminology data for the custom terminology being imported.</p>
    pub terminology_data: ::std::option::Option<crate::types::TerminologyData>,
    /// <p>The encryption key for the custom terminology being imported.</p>
    pub encryption_key: ::std::option::Option<crate::types::EncryptionKey>,
    /// <p>Tags to be associated with this resource. A tag is a key-value pair that adds metadata to a resource. Each tag key for the resource must be unique. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/tagging.html"> Tagging your resources</a>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl ImportTerminologyInput {
    /// <p>The name of the custom terminology being imported.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The merge strategy of the custom terminology being imported. Currently, only the OVERWRITE merge strategy is supported. In this case, the imported terminology will overwrite an existing terminology of the same name.</p>
    pub fn merge_strategy(&self) -> ::std::option::Option<&crate::types::MergeStrategy> {
        self.merge_strategy.as_ref()
    }
    /// <p>The description of the custom terminology being imported.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The terminology data for the custom terminology being imported.</p>
    pub fn terminology_data(&self) -> ::std::option::Option<&crate::types::TerminologyData> {
        self.terminology_data.as_ref()
    }
    /// <p>The encryption key for the custom terminology being imported.</p>
    pub fn encryption_key(&self) -> ::std::option::Option<&crate::types::EncryptionKey> {
        self.encryption_key.as_ref()
    }
    /// <p>Tags to be associated with this resource. A tag is a key-value pair that adds metadata to a resource. Each tag key for the resource must be unique. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/tagging.html"> Tagging your resources</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ImportTerminologyInput {
    /// Creates a new builder-style object to manufacture [`ImportTerminologyInput`](crate::operation::import_terminology::ImportTerminologyInput).
    pub fn builder() -> crate::operation::import_terminology::builders::ImportTerminologyInputBuilder {
        crate::operation::import_terminology::builders::ImportTerminologyInputBuilder::default()
    }
}

/// A builder for [`ImportTerminologyInput`](crate::operation::import_terminology::ImportTerminologyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportTerminologyInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) merge_strategy: ::std::option::Option<crate::types::MergeStrategy>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) terminology_data: ::std::option::Option<crate::types::TerminologyData>,
    pub(crate) encryption_key: ::std::option::Option<crate::types::EncryptionKey>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl ImportTerminologyInputBuilder {
    /// <p>The name of the custom terminology being imported.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom terminology being imported.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the custom terminology being imported.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The merge strategy of the custom terminology being imported. Currently, only the OVERWRITE merge strategy is supported. In this case, the imported terminology will overwrite an existing terminology of the same name.</p>
    /// This field is required.
    pub fn merge_strategy(mut self, input: crate::types::MergeStrategy) -> Self {
        self.merge_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The merge strategy of the custom terminology being imported. Currently, only the OVERWRITE merge strategy is supported. In this case, the imported terminology will overwrite an existing terminology of the same name.</p>
    pub fn set_merge_strategy(mut self, input: ::std::option::Option<crate::types::MergeStrategy>) -> Self {
        self.merge_strategy = input;
        self
    }
    /// <p>The merge strategy of the custom terminology being imported. Currently, only the OVERWRITE merge strategy is supported. In this case, the imported terminology will overwrite an existing terminology of the same name.</p>
    pub fn get_merge_strategy(&self) -> &::std::option::Option<crate::types::MergeStrategy> {
        &self.merge_strategy
    }
    /// <p>The description of the custom terminology being imported.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the custom terminology being imported.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the custom terminology being imported.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The terminology data for the custom terminology being imported.</p>
    /// This field is required.
    pub fn terminology_data(mut self, input: crate::types::TerminologyData) -> Self {
        self.terminology_data = ::std::option::Option::Some(input);
        self
    }
    /// <p>The terminology data for the custom terminology being imported.</p>
    pub fn set_terminology_data(mut self, input: ::std::option::Option<crate::types::TerminologyData>) -> Self {
        self.terminology_data = input;
        self
    }
    /// <p>The terminology data for the custom terminology being imported.</p>
    pub fn get_terminology_data(&self) -> &::std::option::Option<crate::types::TerminologyData> {
        &self.terminology_data
    }
    /// <p>The encryption key for the custom terminology being imported.</p>
    pub fn encryption_key(mut self, input: crate::types::EncryptionKey) -> Self {
        self.encryption_key = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption key for the custom terminology being imported.</p>
    pub fn set_encryption_key(mut self, input: ::std::option::Option<crate::types::EncryptionKey>) -> Self {
        self.encryption_key = input;
        self
    }
    /// <p>The encryption key for the custom terminology being imported.</p>
    pub fn get_encryption_key(&self) -> &::std::option::Option<crate::types::EncryptionKey> {
        &self.encryption_key
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags to be associated with this resource. A tag is a key-value pair that adds metadata to a resource. Each tag key for the resource must be unique. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/tagging.html"> Tagging your resources</a>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Tags to be associated with this resource. A tag is a key-value pair that adds metadata to a resource. Each tag key for the resource must be unique. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/tagging.html"> Tagging your resources</a>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags to be associated with this resource. A tag is a key-value pair that adds metadata to a resource. Each tag key for the resource must be unique. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/tagging.html"> Tagging your resources</a>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`ImportTerminologyInput`](crate::operation::import_terminology::ImportTerminologyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::import_terminology::ImportTerminologyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::import_terminology::ImportTerminologyInput {
            name: self.name,
            merge_strategy: self.merge_strategy,
            description: self.description,
            terminology_data: self.terminology_data,
            encryption_key: self.encryption_key,
            tags: self.tags,
        })
    }
}
