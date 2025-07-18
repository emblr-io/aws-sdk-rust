// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTrainingDatasetInput {
    /// <p>The name of the training dataset. This name must be unique in your account and region.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the IAM role that Clean Rooms ML can assume to read the data referred to in the <code>dataSource</code> field of each dataset.</p>
    /// <p>Passing a role across AWS accounts is not allowed. If you pass a role that isn't in your account, you get an <code>AccessDeniedException</code> error.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>An array of information that lists the Dataset objects, which specifies the dataset type and details on its location and schema. You must provide a role that has read access to these tables.</p>
    pub training_data: ::std::option::Option<::std::vec::Vec<crate::types::Dataset>>,
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The description of the training dataset.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl CreateTrainingDatasetInput {
    /// <p>The name of the training dataset. This name must be unique in your account and region.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The ARN of the IAM role that Clean Rooms ML can assume to read the data referred to in the <code>dataSource</code> field of each dataset.</p>
    /// <p>Passing a role across AWS accounts is not allowed. If you pass a role that isn't in your account, you get an <code>AccessDeniedException</code> error.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>An array of information that lists the Dataset objects, which specifies the dataset type and details on its location and schema. You must provide a role that has read access to these tables.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.training_data.is_none()`.
    pub fn training_data(&self) -> &[crate::types::Dataset] {
        self.training_data.as_deref().unwrap_or_default()
    }
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The description of the training dataset.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl CreateTrainingDatasetInput {
    /// Creates a new builder-style object to manufacture [`CreateTrainingDatasetInput`](crate::operation::create_training_dataset::CreateTrainingDatasetInput).
    pub fn builder() -> crate::operation::create_training_dataset::builders::CreateTrainingDatasetInputBuilder {
        crate::operation::create_training_dataset::builders::CreateTrainingDatasetInputBuilder::default()
    }
}

/// A builder for [`CreateTrainingDatasetInput`](crate::operation::create_training_dataset::CreateTrainingDatasetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTrainingDatasetInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) training_data: ::std::option::Option<::std::vec::Vec<crate::types::Dataset>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl CreateTrainingDatasetInputBuilder {
    /// <p>The name of the training dataset. This name must be unique in your account and region.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the training dataset. This name must be unique in your account and region.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the training dataset. This name must be unique in your account and region.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ARN of the IAM role that Clean Rooms ML can assume to read the data referred to in the <code>dataSource</code> field of each dataset.</p>
    /// <p>Passing a role across AWS accounts is not allowed. If you pass a role that isn't in your account, you get an <code>AccessDeniedException</code> error.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM role that Clean Rooms ML can assume to read the data referred to in the <code>dataSource</code> field of each dataset.</p>
    /// <p>Passing a role across AWS accounts is not allowed. If you pass a role that isn't in your account, you get an <code>AccessDeniedException</code> error.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The ARN of the IAM role that Clean Rooms ML can assume to read the data referred to in the <code>dataSource</code> field of each dataset.</p>
    /// <p>Passing a role across AWS accounts is not allowed. If you pass a role that isn't in your account, you get an <code>AccessDeniedException</code> error.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Appends an item to `training_data`.
    ///
    /// To override the contents of this collection use [`set_training_data`](Self::set_training_data).
    ///
    /// <p>An array of information that lists the Dataset objects, which specifies the dataset type and details on its location and schema. You must provide a role that has read access to these tables.</p>
    pub fn training_data(mut self, input: crate::types::Dataset) -> Self {
        let mut v = self.training_data.unwrap_or_default();
        v.push(input);
        self.training_data = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of information that lists the Dataset objects, which specifies the dataset type and details on its location and schema. You must provide a role that has read access to these tables.</p>
    pub fn set_training_data(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Dataset>>) -> Self {
        self.training_data = input;
        self
    }
    /// <p>An array of information that lists the Dataset objects, which specifies the dataset type and details on its location and schema. You must provide a role that has read access to these tables.</p>
    pub fn get_training_data(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Dataset>> {
        &self.training_data
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The optional metadata that you apply to the resource to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
    /// <p>The following basic restrictions apply to tags:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum number of tags per resource - 50.</p></li>
    /// <li>
    /// <p>For each resource, each tag key must be unique, and each tag key can have only one value.</p></li>
    /// <li>
    /// <p>Maximum key length - 128 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>Maximum value length - 256 Unicode characters in UTF-8.</p></li>
    /// <li>
    /// <p>If your tagging schema is used across multiple services and resources, remember that other services may have restrictions on allowed characters. Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Tag keys and values are case sensitive.</p></li>
    /// <li>
    /// <p>Do not use aws:, AWS:, or any upper or lowercase combination of such as a prefix for keys as it is reserved for AWS use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has aws as its prefix but the key does not, then Clean Rooms ML considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of aws do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The description of the training dataset.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the training dataset.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the training dataset.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`CreateTrainingDatasetInput`](crate::operation::create_training_dataset::CreateTrainingDatasetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_training_dataset::CreateTrainingDatasetInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_training_dataset::CreateTrainingDatasetInput {
            name: self.name,
            role_arn: self.role_arn,
            training_data: self.training_data,
            tags: self.tags,
            description: self.description,
        })
    }
}
