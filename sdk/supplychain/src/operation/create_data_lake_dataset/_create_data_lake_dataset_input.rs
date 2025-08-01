// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request parameters for CreateDataLakeDataset.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDataLakeDatasetInput {
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The namespace of the dataset, besides the custom defined namespace, every instance comes with below pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - For information on the Amazon Web Services Supply Chain supported datasets see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - For datasets with custom user-defined schemas.</p></li>
    /// </ul>
    pub namespace: ::std::option::Option<::std::string::String>,
    /// <p>The name of the dataset. For <b>asc</b> name space, the name must be one of the supported data entities under <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The custom schema of the data lake dataset and required for dataset in <b>default</b> and custom namespaces.</p>
    pub schema: ::std::option::Option<crate::types::DataLakeDatasetSchema>,
    /// <p>The description of the dataset.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The partition specification of the dataset. Partitioning can effectively improve the dataset query performance by reducing the amount of data scanned during query execution. But partitioning or not will affect how data get ingested by data ingestion methods, such as SendDataIntegrationEvent's dataset UPSERT will upsert records within partition (instead of within whole dataset). For more details, refer to those data ingestion documentations.</p>
    pub partition_spec: ::std::option::Option<crate::types::DataLakeDatasetPartitionSpec>,
    /// <p>The tags of the dataset.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateDataLakeDatasetInput {
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The namespace of the dataset, besides the custom defined namespace, every instance comes with below pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - For information on the Amazon Web Services Supply Chain supported datasets see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - For datasets with custom user-defined schemas.</p></li>
    /// </ul>
    pub fn namespace(&self) -> ::std::option::Option<&str> {
        self.namespace.as_deref()
    }
    /// <p>The name of the dataset. For <b>asc</b> name space, the name must be one of the supported data entities under <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The custom schema of the data lake dataset and required for dataset in <b>default</b> and custom namespaces.</p>
    pub fn schema(&self) -> ::std::option::Option<&crate::types::DataLakeDatasetSchema> {
        self.schema.as_ref()
    }
    /// <p>The description of the dataset.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The partition specification of the dataset. Partitioning can effectively improve the dataset query performance by reducing the amount of data scanned during query execution. But partitioning or not will affect how data get ingested by data ingestion methods, such as SendDataIntegrationEvent's dataset UPSERT will upsert records within partition (instead of within whole dataset). For more details, refer to those data ingestion documentations.</p>
    pub fn partition_spec(&self) -> ::std::option::Option<&crate::types::DataLakeDatasetPartitionSpec> {
        self.partition_spec.as_ref()
    }
    /// <p>The tags of the dataset.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateDataLakeDatasetInput {
    /// Creates a new builder-style object to manufacture [`CreateDataLakeDatasetInput`](crate::operation::create_data_lake_dataset::CreateDataLakeDatasetInput).
    pub fn builder() -> crate::operation::create_data_lake_dataset::builders::CreateDataLakeDatasetInputBuilder {
        crate::operation::create_data_lake_dataset::builders::CreateDataLakeDatasetInputBuilder::default()
    }
}

/// A builder for [`CreateDataLakeDatasetInput`](crate::operation::create_data_lake_dataset::CreateDataLakeDatasetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDataLakeDatasetInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) namespace: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) schema: ::std::option::Option<crate::types::DataLakeDatasetSchema>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) partition_spec: ::std::option::Option<crate::types::DataLakeDatasetPartitionSpec>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateDataLakeDatasetInputBuilder {
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The Amazon Web Services Supply Chain instance identifier.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The namespace of the dataset, besides the custom defined namespace, every instance comes with below pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - For information on the Amazon Web Services Supply Chain supported datasets see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - For datasets with custom user-defined schemas.</p></li>
    /// </ul>
    /// This field is required.
    pub fn namespace(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace of the dataset, besides the custom defined namespace, every instance comes with below pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - For information on the Amazon Web Services Supply Chain supported datasets see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - For datasets with custom user-defined schemas.</p></li>
    /// </ul>
    pub fn set_namespace(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace = input;
        self
    }
    /// <p>The namespace of the dataset, besides the custom defined namespace, every instance comes with below pre-defined namespaces:</p>
    /// <ul>
    /// <li>
    /// <p><b>asc</b> - For information on the Amazon Web Services Supply Chain supported datasets see <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p></li>
    /// <li>
    /// <p><b>default</b> - For datasets with custom user-defined schemas.</p></li>
    /// </ul>
    pub fn get_namespace(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace
    }
    /// <p>The name of the dataset. For <b>asc</b> name space, the name must be one of the supported data entities under <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the dataset. For <b>asc</b> name space, the name must be one of the supported data entities under <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the dataset. For <b>asc</b> name space, the name must be one of the supported data entities under <a href="https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html">https://docs.aws.amazon.com/aws-supply-chain/latest/userguide/data-model-asc.html</a>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The custom schema of the data lake dataset and required for dataset in <b>default</b> and custom namespaces.</p>
    pub fn schema(mut self, input: crate::types::DataLakeDatasetSchema) -> Self {
        self.schema = ::std::option::Option::Some(input);
        self
    }
    /// <p>The custom schema of the data lake dataset and required for dataset in <b>default</b> and custom namespaces.</p>
    pub fn set_schema(mut self, input: ::std::option::Option<crate::types::DataLakeDatasetSchema>) -> Self {
        self.schema = input;
        self
    }
    /// <p>The custom schema of the data lake dataset and required for dataset in <b>default</b> and custom namespaces.</p>
    pub fn get_schema(&self) -> &::std::option::Option<crate::types::DataLakeDatasetSchema> {
        &self.schema
    }
    /// <p>The description of the dataset.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the dataset.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the dataset.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The partition specification of the dataset. Partitioning can effectively improve the dataset query performance by reducing the amount of data scanned during query execution. But partitioning or not will affect how data get ingested by data ingestion methods, such as SendDataIntegrationEvent's dataset UPSERT will upsert records within partition (instead of within whole dataset). For more details, refer to those data ingestion documentations.</p>
    pub fn partition_spec(mut self, input: crate::types::DataLakeDatasetPartitionSpec) -> Self {
        self.partition_spec = ::std::option::Option::Some(input);
        self
    }
    /// <p>The partition specification of the dataset. Partitioning can effectively improve the dataset query performance by reducing the amount of data scanned during query execution. But partitioning or not will affect how data get ingested by data ingestion methods, such as SendDataIntegrationEvent's dataset UPSERT will upsert records within partition (instead of within whole dataset). For more details, refer to those data ingestion documentations.</p>
    pub fn set_partition_spec(mut self, input: ::std::option::Option<crate::types::DataLakeDatasetPartitionSpec>) -> Self {
        self.partition_spec = input;
        self
    }
    /// <p>The partition specification of the dataset. Partitioning can effectively improve the dataset query performance by reducing the amount of data scanned during query execution. But partitioning or not will affect how data get ingested by data ingestion methods, such as SendDataIntegrationEvent's dataset UPSERT will upsert records within partition (instead of within whole dataset). For more details, refer to those data ingestion documentations.</p>
    pub fn get_partition_spec(&self) -> &::std::option::Option<crate::types::DataLakeDatasetPartitionSpec> {
        &self.partition_spec
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags of the dataset.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags of the dataset.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags of the dataset.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateDataLakeDatasetInput`](crate::operation::create_data_lake_dataset::CreateDataLakeDatasetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_data_lake_dataset::CreateDataLakeDatasetInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_data_lake_dataset::CreateDataLakeDatasetInput {
            instance_id: self.instance_id,
            namespace: self.namespace,
            name: self.name,
            schema: self.schema,
            description: self.description,
            partition_spec: self.partition_spec,
            tags: self.tags,
        })
    }
}
