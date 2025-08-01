// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// The request for an UpdateDataset operation
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDatasetInput {
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the Dataset to update.</p>
    pub dataset_id: ::std::option::Option<::std::string::String>,
    /// <p>A display title for the Dataset.</p>
    pub dataset_title: ::std::option::Option<::std::string::String>,
    /// <p>The format in which the Dataset data is structured.</p>
    /// <ul>
    /// <li>
    /// <p><code>TABULAR</code> – Data is structured in a tabular format.</p></li>
    /// <li>
    /// <p><code>NON_TABULAR</code> – Data is structured in a non-tabular format.</p></li>
    /// </ul>
    pub kind: ::std::option::Option<crate::types::DatasetKind>,
    /// <p>A description for the Dataset.</p>
    pub dataset_description: ::std::option::Option<::std::string::String>,
    /// <p>The unique resource identifier for a Dataset.</p>
    pub alias: ::std::option::Option<::std::string::String>,
    /// <p>Definition for a schema on a tabular Dataset.</p>
    pub schema_definition: ::std::option::Option<crate::types::SchemaUnion>,
}
impl UpdateDatasetInput {
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The unique identifier for the Dataset to update.</p>
    pub fn dataset_id(&self) -> ::std::option::Option<&str> {
        self.dataset_id.as_deref()
    }
    /// <p>A display title for the Dataset.</p>
    pub fn dataset_title(&self) -> ::std::option::Option<&str> {
        self.dataset_title.as_deref()
    }
    /// <p>The format in which the Dataset data is structured.</p>
    /// <ul>
    /// <li>
    /// <p><code>TABULAR</code> – Data is structured in a tabular format.</p></li>
    /// <li>
    /// <p><code>NON_TABULAR</code> – Data is structured in a non-tabular format.</p></li>
    /// </ul>
    pub fn kind(&self) -> ::std::option::Option<&crate::types::DatasetKind> {
        self.kind.as_ref()
    }
    /// <p>A description for the Dataset.</p>
    pub fn dataset_description(&self) -> ::std::option::Option<&str> {
        self.dataset_description.as_deref()
    }
    /// <p>The unique resource identifier for a Dataset.</p>
    pub fn alias(&self) -> ::std::option::Option<&str> {
        self.alias.as_deref()
    }
    /// <p>Definition for a schema on a tabular Dataset.</p>
    pub fn schema_definition(&self) -> ::std::option::Option<&crate::types::SchemaUnion> {
        self.schema_definition.as_ref()
    }
}
impl UpdateDatasetInput {
    /// Creates a new builder-style object to manufacture [`UpdateDatasetInput`](crate::operation::update_dataset::UpdateDatasetInput).
    pub fn builder() -> crate::operation::update_dataset::builders::UpdateDatasetInputBuilder {
        crate::operation::update_dataset::builders::UpdateDatasetInputBuilder::default()
    }
}

/// A builder for [`UpdateDatasetInput`](crate::operation::update_dataset::UpdateDatasetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDatasetInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_id: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_title: ::std::option::Option<::std::string::String>,
    pub(crate) kind: ::std::option::Option<crate::types::DatasetKind>,
    pub(crate) dataset_description: ::std::option::Option<::std::string::String>,
    pub(crate) alias: ::std::option::Option<::std::string::String>,
    pub(crate) schema_definition: ::std::option::Option<crate::types::SchemaUnion>,
}
impl UpdateDatasetInputBuilder {
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A token that ensures idempotency. This token expires in 10 minutes.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The unique identifier for the Dataset to update.</p>
    /// This field is required.
    pub fn dataset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the Dataset to update.</p>
    pub fn set_dataset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_id = input;
        self
    }
    /// <p>The unique identifier for the Dataset to update.</p>
    pub fn get_dataset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_id
    }
    /// <p>A display title for the Dataset.</p>
    /// This field is required.
    pub fn dataset_title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A display title for the Dataset.</p>
    pub fn set_dataset_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_title = input;
        self
    }
    /// <p>A display title for the Dataset.</p>
    pub fn get_dataset_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_title
    }
    /// <p>The format in which the Dataset data is structured.</p>
    /// <ul>
    /// <li>
    /// <p><code>TABULAR</code> – Data is structured in a tabular format.</p></li>
    /// <li>
    /// <p><code>NON_TABULAR</code> – Data is structured in a non-tabular format.</p></li>
    /// </ul>
    /// This field is required.
    pub fn kind(mut self, input: crate::types::DatasetKind) -> Self {
        self.kind = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format in which the Dataset data is structured.</p>
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
    /// <p>The format in which the Dataset data is structured.</p>
    /// <ul>
    /// <li>
    /// <p><code>TABULAR</code> – Data is structured in a tabular format.</p></li>
    /// <li>
    /// <p><code>NON_TABULAR</code> – Data is structured in a non-tabular format.</p></li>
    /// </ul>
    pub fn get_kind(&self) -> &::std::option::Option<crate::types::DatasetKind> {
        &self.kind
    }
    /// <p>A description for the Dataset.</p>
    pub fn dataset_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the Dataset.</p>
    pub fn set_dataset_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_description = input;
        self
    }
    /// <p>A description for the Dataset.</p>
    pub fn get_dataset_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_description
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
    /// Consumes the builder and constructs a [`UpdateDatasetInput`](crate::operation::update_dataset::UpdateDatasetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_dataset::UpdateDatasetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_dataset::UpdateDatasetInput {
            client_token: self.client_token,
            dataset_id: self.dataset_id,
            dataset_title: self.dataset_title,
            kind: self.kind,
            dataset_description: self.dataset_description,
            alias: self.alias,
            schema_definition: self.schema_definition,
        })
    }
}
