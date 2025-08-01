// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The structure for a Dataset.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Dataset {
    /// <p>An identifier for a Dataset.</p>
    pub dataset_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN identifier of the Dataset.</p>
    pub dataset_arn: ::std::option::Option<::std::string::String>,
    /// <p>Display title for a Dataset.</p>
    pub dataset_title: ::std::option::Option<::std::string::String>,
    /// <p>The format in which Dataset data is structured.</p>
    /// <ul>
    /// <li>
    /// <p><code>TABULAR</code> – Data is structured in a tabular format.</p></li>
    /// <li>
    /// <p><code>NON_TABULAR</code> – Data is structured in a non-tabular format.</p></li>
    /// </ul>
    pub kind: ::std::option::Option<crate::types::DatasetKind>,
    /// <p>Description for a Dataset.</p>
    pub dataset_description: ::std::option::Option<::std::string::String>,
    /// <p>Contact information for a Dataset owner.</p>
    pub owner_info: ::std::option::Option<crate::types::DatasetOwnerInfo>,
    /// <p>The timestamp at which the Dataset was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub create_time: i64,
    /// <p>The last time that the Dataset was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub last_modified_time: i64,
    /// <p>Definition for a schema on a tabular Dataset.</p>
    pub schema_definition: ::std::option::Option<crate::types::SchemaUnion>,
    /// <p>The unique resource identifier for a Dataset.</p>
    pub alias: ::std::option::Option<::std::string::String>,
}
impl Dataset {
    /// <p>An identifier for a Dataset.</p>
    pub fn dataset_id(&self) -> ::std::option::Option<&str> {
        self.dataset_id.as_deref()
    }
    /// <p>The ARN identifier of the Dataset.</p>
    pub fn dataset_arn(&self) -> ::std::option::Option<&str> {
        self.dataset_arn.as_deref()
    }
    /// <p>Display title for a Dataset.</p>
    pub fn dataset_title(&self) -> ::std::option::Option<&str> {
        self.dataset_title.as_deref()
    }
    /// <p>The format in which Dataset data is structured.</p>
    /// <ul>
    /// <li>
    /// <p><code>TABULAR</code> – Data is structured in a tabular format.</p></li>
    /// <li>
    /// <p><code>NON_TABULAR</code> – Data is structured in a non-tabular format.</p></li>
    /// </ul>
    pub fn kind(&self) -> ::std::option::Option<&crate::types::DatasetKind> {
        self.kind.as_ref()
    }
    /// <p>Description for a Dataset.</p>
    pub fn dataset_description(&self) -> ::std::option::Option<&str> {
        self.dataset_description.as_deref()
    }
    /// <p>Contact information for a Dataset owner.</p>
    pub fn owner_info(&self) -> ::std::option::Option<&crate::types::DatasetOwnerInfo> {
        self.owner_info.as_ref()
    }
    /// <p>The timestamp at which the Dataset was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn create_time(&self) -> i64 {
        self.create_time
    }
    /// <p>The last time that the Dataset was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn last_modified_time(&self) -> i64 {
        self.last_modified_time
    }
    /// <p>Definition for a schema on a tabular Dataset.</p>
    pub fn schema_definition(&self) -> ::std::option::Option<&crate::types::SchemaUnion> {
        self.schema_definition.as_ref()
    }
    /// <p>The unique resource identifier for a Dataset.</p>
    pub fn alias(&self) -> ::std::option::Option<&str> {
        self.alias.as_deref()
    }
}
impl Dataset {
    /// Creates a new builder-style object to manufacture [`Dataset`](crate::types::Dataset).
    pub fn builder() -> crate::types::builders::DatasetBuilder {
        crate::types::builders::DatasetBuilder::default()
    }
}

/// A builder for [`Dataset`](crate::types::Dataset).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DatasetBuilder {
    pub(crate) dataset_id: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_arn: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_title: ::std::option::Option<::std::string::String>,
    pub(crate) kind: ::std::option::Option<crate::types::DatasetKind>,
    pub(crate) dataset_description: ::std::option::Option<::std::string::String>,
    pub(crate) owner_info: ::std::option::Option<crate::types::DatasetOwnerInfo>,
    pub(crate) create_time: ::std::option::Option<i64>,
    pub(crate) last_modified_time: ::std::option::Option<i64>,
    pub(crate) schema_definition: ::std::option::Option<crate::types::SchemaUnion>,
    pub(crate) alias: ::std::option::Option<::std::string::String>,
}
impl DatasetBuilder {
    /// <p>An identifier for a Dataset.</p>
    pub fn dataset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier for a Dataset.</p>
    pub fn set_dataset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_id = input;
        self
    }
    /// <p>An identifier for a Dataset.</p>
    pub fn get_dataset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_id
    }
    /// <p>The ARN identifier of the Dataset.</p>
    pub fn dataset_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN identifier of the Dataset.</p>
    pub fn set_dataset_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_arn = input;
        self
    }
    /// <p>The ARN identifier of the Dataset.</p>
    pub fn get_dataset_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_arn
    }
    /// <p>Display title for a Dataset.</p>
    pub fn dataset_title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Display title for a Dataset.</p>
    pub fn set_dataset_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_title = input;
        self
    }
    /// <p>Display title for a Dataset.</p>
    pub fn get_dataset_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_title
    }
    /// <p>The format in which Dataset data is structured.</p>
    /// <ul>
    /// <li>
    /// <p><code>TABULAR</code> – Data is structured in a tabular format.</p></li>
    /// <li>
    /// <p><code>NON_TABULAR</code> – Data is structured in a non-tabular format.</p></li>
    /// </ul>
    pub fn kind(mut self, input: crate::types::DatasetKind) -> Self {
        self.kind = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format in which Dataset data is structured.</p>
    /// <ul>
    /// <li>
    /// <p><code>TABULAR</code> – Data is structured in a tabular format.</p></li>
    /// <li>
    /// <p><code>NON_TABULAR</code> – Data is structured in a non-tabular format.</p></li>
    /// </ul>
    pub fn set_kind(mut self, input: ::std::option::Option<crate::types::DatasetKind>) -> Self {
        self.kind = input;
        self
    }
    /// <p>The format in which Dataset data is structured.</p>
    /// <ul>
    /// <li>
    /// <p><code>TABULAR</code> – Data is structured in a tabular format.</p></li>
    /// <li>
    /// <p><code>NON_TABULAR</code> – Data is structured in a non-tabular format.</p></li>
    /// </ul>
    pub fn get_kind(&self) -> &::std::option::Option<crate::types::DatasetKind> {
        &self.kind
    }
    /// <p>Description for a Dataset.</p>
    pub fn dataset_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Description for a Dataset.</p>
    pub fn set_dataset_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_description = input;
        self
    }
    /// <p>Description for a Dataset.</p>
    pub fn get_dataset_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_description
    }
    /// <p>Contact information for a Dataset owner.</p>
    pub fn owner_info(mut self, input: crate::types::DatasetOwnerInfo) -> Self {
        self.owner_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contact information for a Dataset owner.</p>
    pub fn set_owner_info(mut self, input: ::std::option::Option<crate::types::DatasetOwnerInfo>) -> Self {
        self.owner_info = input;
        self
    }
    /// <p>Contact information for a Dataset owner.</p>
    pub fn get_owner_info(&self) -> &::std::option::Option<crate::types::DatasetOwnerInfo> {
        &self.owner_info
    }
    /// <p>The timestamp at which the Dataset was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn create_time(mut self, input: i64) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the Dataset was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The timestamp at which the Dataset was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<i64> {
        &self.create_time
    }
    /// <p>The last time that the Dataset was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn last_modified_time(mut self, input: i64) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time that the Dataset was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The last time that the Dataset was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<i64> {
        &self.last_modified_time
    }
    /// <p>Definition for a schema on a tabular Dataset.</p>
    pub fn schema_definition(mut self, input: crate::types::SchemaUnion) -> Self {
        self.schema_definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>Definition for a schema on a tabular Dataset.</p>
    pub fn set_schema_definition(mut self, input: ::std::option::Option<crate::types::SchemaUnion>) -> Self {
        self.schema_definition = input;
        self
    }
    /// <p>Definition for a schema on a tabular Dataset.</p>
    pub fn get_schema_definition(&self) -> &::std::option::Option<crate::types::SchemaUnion> {
        &self.schema_definition
    }
    /// <p>The unique resource identifier for a Dataset.</p>
    pub fn alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique resource identifier for a Dataset.</p>
    pub fn set_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias = input;
        self
    }
    /// <p>The unique resource identifier for a Dataset.</p>
    pub fn get_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias
    }
    /// Consumes the builder and constructs a [`Dataset`](crate::types::Dataset).
    pub fn build(self) -> crate::types::Dataset {
        crate::types::Dataset {
            dataset_id: self.dataset_id,
            dataset_arn: self.dataset_arn,
            dataset_title: self.dataset_title,
            kind: self.kind,
            dataset_description: self.dataset_description,
            owner_info: self.owner_info,
            create_time: self.create_time.unwrap_or_default(),
            last_modified_time: self.last_modified_time.unwrap_or_default(),
            schema_definition: self.schema_definition,
            alias: self.alias,
        }
    }
}
