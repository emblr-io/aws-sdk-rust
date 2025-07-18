// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDataLakeInput {
    /// <p>Specifies the Region or Regions that will contribute data to the rollup region.</p>
    pub configurations: ::std::option::Option<::std::vec::Vec<crate::types::DataLakeConfiguration>>,
    /// <p>The Amazon Resource Name (ARN) used to create and update the Glue table. This table contains partitions generated by the ingestion and normalization of Amazon Web Services log sources and custom sources.</p>
    pub meta_store_manager_role_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateDataLakeInput {
    /// <p>Specifies the Region or Regions that will contribute data to the rollup region.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.configurations.is_none()`.
    pub fn configurations(&self) -> &[crate::types::DataLakeConfiguration] {
        self.configurations.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) used to create and update the Glue table. This table contains partitions generated by the ingestion and normalization of Amazon Web Services log sources and custom sources.</p>
    pub fn meta_store_manager_role_arn(&self) -> ::std::option::Option<&str> {
        self.meta_store_manager_role_arn.as_deref()
    }
}
impl UpdateDataLakeInput {
    /// Creates a new builder-style object to manufacture [`UpdateDataLakeInput`](crate::operation::update_data_lake::UpdateDataLakeInput).
    pub fn builder() -> crate::operation::update_data_lake::builders::UpdateDataLakeInputBuilder {
        crate::operation::update_data_lake::builders::UpdateDataLakeInputBuilder::default()
    }
}

/// A builder for [`UpdateDataLakeInput`](crate::operation::update_data_lake::UpdateDataLakeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDataLakeInputBuilder {
    pub(crate) configurations: ::std::option::Option<::std::vec::Vec<crate::types::DataLakeConfiguration>>,
    pub(crate) meta_store_manager_role_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateDataLakeInputBuilder {
    /// Appends an item to `configurations`.
    ///
    /// To override the contents of this collection use [`set_configurations`](Self::set_configurations).
    ///
    /// <p>Specifies the Region or Regions that will contribute data to the rollup region.</p>
    pub fn configurations(mut self, input: crate::types::DataLakeConfiguration) -> Self {
        let mut v = self.configurations.unwrap_or_default();
        v.push(input);
        self.configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the Region or Regions that will contribute data to the rollup region.</p>
    pub fn set_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataLakeConfiguration>>) -> Self {
        self.configurations = input;
        self
    }
    /// <p>Specifies the Region or Regions that will contribute data to the rollup region.</p>
    pub fn get_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataLakeConfiguration>> {
        &self.configurations
    }
    /// <p>The Amazon Resource Name (ARN) used to create and update the Glue table. This table contains partitions generated by the ingestion and normalization of Amazon Web Services log sources and custom sources.</p>
    pub fn meta_store_manager_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.meta_store_manager_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) used to create and update the Glue table. This table contains partitions generated by the ingestion and normalization of Amazon Web Services log sources and custom sources.</p>
    pub fn set_meta_store_manager_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.meta_store_manager_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) used to create and update the Glue table. This table contains partitions generated by the ingestion and normalization of Amazon Web Services log sources and custom sources.</p>
    pub fn get_meta_store_manager_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.meta_store_manager_role_arn
    }
    /// Consumes the builder and constructs a [`UpdateDataLakeInput`](crate::operation::update_data_lake::UpdateDataLakeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_data_lake::UpdateDataLakeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_data_lake::UpdateDataLakeInput {
            configurations: self.configurations,
            meta_store_manager_role_arn: self.meta_store_manager_role_arn,
        })
    }
}
