// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDataCatalogInput {
    /// <p>The name of the data catalog to update. The catalog name must be unique for the Amazon Web Services account and can use a maximum of 127 alphanumeric, underscore, at sign, or hyphen characters. The remainder of the length constraint of 256 is reserved for use by Athena.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the type of data catalog to update. Specify <code>LAMBDA</code> for a federated catalog, <code>HIVE</code> for an external hive metastore, or <code>GLUE</code> for an Glue Data Catalog.</p>
    pub r#type: ::std::option::Option<crate::types::DataCatalogType>,
    /// <p>New or modified text that describes the data catalog.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the Lambda function or functions to use for updating the data catalog. This is a mapping whose values depend on the catalog type.</p>
    /// <ul>
    /// <li>
    /// <p>For the <code>HIVE</code> data catalog type, use the following syntax. The <code>metadata-function</code> parameter is required. <code>The sdk-version</code> parameter is optional and defaults to the currently supported version.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, sdk-version=<i>version_number</i> </code></p></li>
    /// <li>
    /// <p>For the <code>LAMBDA</code> data catalog type, use one of the following sets of required parameters, but not both.</p>
    /// <ul>
    /// <li>
    /// <p>If you have one Lambda function that processes metadata and another for reading the actual data, use the following syntax. Both parameters are required.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, record-function=<i>lambda_arn</i> </code></p></li>
    /// <li>
    /// <p>If you have a composite Lambda function that processes both metadata and data, use the following syntax to specify your Lambda function.</p>
    /// <p><code>function=<i>lambda_arn</i> </code></p></li>
    /// </ul></li>
    /// </ul>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateDataCatalogInput {
    /// <p>The name of the data catalog to update. The catalog name must be unique for the Amazon Web Services account and can use a maximum of 127 alphanumeric, underscore, at sign, or hyphen characters. The remainder of the length constraint of 256 is reserved for use by Athena.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Specifies the type of data catalog to update. Specify <code>LAMBDA</code> for a federated catalog, <code>HIVE</code> for an external hive metastore, or <code>GLUE</code> for an Glue Data Catalog.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::DataCatalogType> {
        self.r#type.as_ref()
    }
    /// <p>New or modified text that describes the data catalog.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Specifies the Lambda function or functions to use for updating the data catalog. This is a mapping whose values depend on the catalog type.</p>
    /// <ul>
    /// <li>
    /// <p>For the <code>HIVE</code> data catalog type, use the following syntax. The <code>metadata-function</code> parameter is required. <code>The sdk-version</code> parameter is optional and defaults to the currently supported version.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, sdk-version=<i>version_number</i> </code></p></li>
    /// <li>
    /// <p>For the <code>LAMBDA</code> data catalog type, use one of the following sets of required parameters, but not both.</p>
    /// <ul>
    /// <li>
    /// <p>If you have one Lambda function that processes metadata and another for reading the actual data, use the following syntax. Both parameters are required.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, record-function=<i>lambda_arn</i> </code></p></li>
    /// <li>
    /// <p>If you have a composite Lambda function that processes both metadata and data, use the following syntax to specify your Lambda function.</p>
    /// <p><code>function=<i>lambda_arn</i> </code></p></li>
    /// </ul></li>
    /// </ul>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.parameters.as_ref()
    }
}
impl UpdateDataCatalogInput {
    /// Creates a new builder-style object to manufacture [`UpdateDataCatalogInput`](crate::operation::update_data_catalog::UpdateDataCatalogInput).
    pub fn builder() -> crate::operation::update_data_catalog::builders::UpdateDataCatalogInputBuilder {
        crate::operation::update_data_catalog::builders::UpdateDataCatalogInputBuilder::default()
    }
}

/// A builder for [`UpdateDataCatalogInput`](crate::operation::update_data_catalog::UpdateDataCatalogInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDataCatalogInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::DataCatalogType>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateDataCatalogInputBuilder {
    /// <p>The name of the data catalog to update. The catalog name must be unique for the Amazon Web Services account and can use a maximum of 127 alphanumeric, underscore, at sign, or hyphen characters. The remainder of the length constraint of 256 is reserved for use by Athena.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data catalog to update. The catalog name must be unique for the Amazon Web Services account and can use a maximum of 127 alphanumeric, underscore, at sign, or hyphen characters. The remainder of the length constraint of 256 is reserved for use by Athena.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the data catalog to update. The catalog name must be unique for the Amazon Web Services account and can use a maximum of 127 alphanumeric, underscore, at sign, or hyphen characters. The remainder of the length constraint of 256 is reserved for use by Athena.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Specifies the type of data catalog to update. Specify <code>LAMBDA</code> for a federated catalog, <code>HIVE</code> for an external hive metastore, or <code>GLUE</code> for an Glue Data Catalog.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::DataCatalogType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the type of data catalog to update. Specify <code>LAMBDA</code> for a federated catalog, <code>HIVE</code> for an external hive metastore, or <code>GLUE</code> for an Glue Data Catalog.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::DataCatalogType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Specifies the type of data catalog to update. Specify <code>LAMBDA</code> for a federated catalog, <code>HIVE</code> for an external hive metastore, or <code>GLUE</code> for an Glue Data Catalog.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::DataCatalogType> {
        &self.r#type
    }
    /// <p>New or modified text that describes the data catalog.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>New or modified text that describes the data catalog.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>New or modified text that describes the data catalog.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>Specifies the Lambda function or functions to use for updating the data catalog. This is a mapping whose values depend on the catalog type.</p>
    /// <ul>
    /// <li>
    /// <p>For the <code>HIVE</code> data catalog type, use the following syntax. The <code>metadata-function</code> parameter is required. <code>The sdk-version</code> parameter is optional and defaults to the currently supported version.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, sdk-version=<i>version_number</i> </code></p></li>
    /// <li>
    /// <p>For the <code>LAMBDA</code> data catalog type, use one of the following sets of required parameters, but not both.</p>
    /// <ul>
    /// <li>
    /// <p>If you have one Lambda function that processes metadata and another for reading the actual data, use the following syntax. Both parameters are required.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, record-function=<i>lambda_arn</i> </code></p></li>
    /// <li>
    /// <p>If you have a composite Lambda function that processes both metadata and data, use the following syntax to specify your Lambda function.</p>
    /// <p><code>function=<i>lambda_arn</i> </code></p></li>
    /// </ul></li>
    /// </ul>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Specifies the Lambda function or functions to use for updating the data catalog. This is a mapping whose values depend on the catalog type.</p>
    /// <ul>
    /// <li>
    /// <p>For the <code>HIVE</code> data catalog type, use the following syntax. The <code>metadata-function</code> parameter is required. <code>The sdk-version</code> parameter is optional and defaults to the currently supported version.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, sdk-version=<i>version_number</i> </code></p></li>
    /// <li>
    /// <p>For the <code>LAMBDA</code> data catalog type, use one of the following sets of required parameters, but not both.</p>
    /// <ul>
    /// <li>
    /// <p>If you have one Lambda function that processes metadata and another for reading the actual data, use the following syntax. Both parameters are required.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, record-function=<i>lambda_arn</i> </code></p></li>
    /// <li>
    /// <p>If you have a composite Lambda function that processes both metadata and data, use the following syntax to specify your Lambda function.</p>
    /// <p><code>function=<i>lambda_arn</i> </code></p></li>
    /// </ul></li>
    /// </ul>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>Specifies the Lambda function or functions to use for updating the data catalog. This is a mapping whose values depend on the catalog type.</p>
    /// <ul>
    /// <li>
    /// <p>For the <code>HIVE</code> data catalog type, use the following syntax. The <code>metadata-function</code> parameter is required. <code>The sdk-version</code> parameter is optional and defaults to the currently supported version.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, sdk-version=<i>version_number</i> </code></p></li>
    /// <li>
    /// <p>For the <code>LAMBDA</code> data catalog type, use one of the following sets of required parameters, but not both.</p>
    /// <ul>
    /// <li>
    /// <p>If you have one Lambda function that processes metadata and another for reading the actual data, use the following syntax. Both parameters are required.</p>
    /// <p><code>metadata-function=<i>lambda_arn</i>, record-function=<i>lambda_arn</i> </code></p></li>
    /// <li>
    /// <p>If you have a composite Lambda function that processes both metadata and data, use the following syntax to specify your Lambda function.</p>
    /// <p><code>function=<i>lambda_arn</i> </code></p></li>
    /// </ul></li>
    /// </ul>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`UpdateDataCatalogInput`](crate::operation::update_data_catalog::UpdateDataCatalogInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_data_catalog::UpdateDataCatalogInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_data_catalog::UpdateDataCatalogInput {
            name: self.name,
            r#type: self.r#type,
            description: self.description,
            parameters: self.parameters,
        })
    }
}
