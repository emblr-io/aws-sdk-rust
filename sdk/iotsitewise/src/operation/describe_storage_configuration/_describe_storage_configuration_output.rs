// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeStorageConfigurationOutput {
    /// <p>The storage tier that you specified for your data. The <code>storageType</code> parameter can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SITEWISE_DEFAULT_STORAGE</code> – IoT SiteWise saves your data into the hot tier. The hot tier is a service-managed database.</p></li>
    /// <li>
    /// <p><code>MULTI_LAYER_STORAGE</code> – IoT SiteWise saves your data in both the cold tier and the hot tier. The cold tier is a customer-managed Amazon S3 bucket.</p></li>
    /// </ul>
    pub storage_type: crate::types::StorageType,
    /// <p>Contains information about the storage destination.</p>
    pub multi_layer_storage: ::std::option::Option<crate::types::MultiLayerStorage>,
    /// <p>Contains the storage configuration for time series (data streams) that aren't associated with asset properties. The <code>disassociatedDataStorage</code> can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – IoT SiteWise accepts time series that aren't associated with asset properties.</p><important>
    /// <p>After the <code>disassociatedDataStorage</code> is enabled, you can't disable it.</p>
    /// </important></li>
    /// <li>
    /// <p><code>DISABLED</code> – IoT SiteWise doesn't accept time series (data streams) that aren't associated with asset properties.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/data-streams.html">Data streams</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub disassociated_data_storage: ::std::option::Option<crate::types::DisassociatedDataStorageState>,
    /// <p>The number of days your data is kept in the hot tier. By default, your data is kept indefinitely in the hot tier.</p>
    pub retention_period: ::std::option::Option<crate::types::RetentionPeriod>,
    /// <p>Contains current status information for the configuration.</p>
    pub configuration_status: ::std::option::Option<crate::types::ConfigurationStatus>,
    /// <p>The date the storage configuration was last updated, in Unix epoch time.</p>
    pub last_update_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A service managed storage tier optimized for analytical queries. It stores periodically uploaded, buffered and historical data ingested with the CreaeBulkImportJob API.</p>
    pub warm_tier: ::std::option::Option<crate::types::WarmTierState>,
    /// <p>Set this period to specify how long your data is stored in the warm tier before it is deleted. You can set this only if cold tier is enabled.</p>
    pub warm_tier_retention_period: ::std::option::Option<crate::types::WarmTierRetentionPeriod>,
    /// <p>Describes the configuration for ingesting NULL and NaN data. By default the feature is allowed. The feature is disallowed if the value is <code>true</code>.</p>
    pub disallow_ingest_null_na_n: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl DescribeStorageConfigurationOutput {
    /// <p>The storage tier that you specified for your data. The <code>storageType</code> parameter can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SITEWISE_DEFAULT_STORAGE</code> – IoT SiteWise saves your data into the hot tier. The hot tier is a service-managed database.</p></li>
    /// <li>
    /// <p><code>MULTI_LAYER_STORAGE</code> – IoT SiteWise saves your data in both the cold tier and the hot tier. The cold tier is a customer-managed Amazon S3 bucket.</p></li>
    /// </ul>
    pub fn storage_type(&self) -> &crate::types::StorageType {
        &self.storage_type
    }
    /// <p>Contains information about the storage destination.</p>
    pub fn multi_layer_storage(&self) -> ::std::option::Option<&crate::types::MultiLayerStorage> {
        self.multi_layer_storage.as_ref()
    }
    /// <p>Contains the storage configuration for time series (data streams) that aren't associated with asset properties. The <code>disassociatedDataStorage</code> can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – IoT SiteWise accepts time series that aren't associated with asset properties.</p><important>
    /// <p>After the <code>disassociatedDataStorage</code> is enabled, you can't disable it.</p>
    /// </important></li>
    /// <li>
    /// <p><code>DISABLED</code> – IoT SiteWise doesn't accept time series (data streams) that aren't associated with asset properties.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/data-streams.html">Data streams</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn disassociated_data_storage(&self) -> ::std::option::Option<&crate::types::DisassociatedDataStorageState> {
        self.disassociated_data_storage.as_ref()
    }
    /// <p>The number of days your data is kept in the hot tier. By default, your data is kept indefinitely in the hot tier.</p>
    pub fn retention_period(&self) -> ::std::option::Option<&crate::types::RetentionPeriod> {
        self.retention_period.as_ref()
    }
    /// <p>Contains current status information for the configuration.</p>
    pub fn configuration_status(&self) -> ::std::option::Option<&crate::types::ConfigurationStatus> {
        self.configuration_status.as_ref()
    }
    /// <p>The date the storage configuration was last updated, in Unix epoch time.</p>
    pub fn last_update_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_update_date.as_ref()
    }
    /// <p>A service managed storage tier optimized for analytical queries. It stores periodically uploaded, buffered and historical data ingested with the CreaeBulkImportJob API.</p>
    pub fn warm_tier(&self) -> ::std::option::Option<&crate::types::WarmTierState> {
        self.warm_tier.as_ref()
    }
    /// <p>Set this period to specify how long your data is stored in the warm tier before it is deleted. You can set this only if cold tier is enabled.</p>
    pub fn warm_tier_retention_period(&self) -> ::std::option::Option<&crate::types::WarmTierRetentionPeriod> {
        self.warm_tier_retention_period.as_ref()
    }
    /// <p>Describes the configuration for ingesting NULL and NaN data. By default the feature is allowed. The feature is disallowed if the value is <code>true</code>.</p>
    pub fn disallow_ingest_null_na_n(&self) -> ::std::option::Option<bool> {
        self.disallow_ingest_null_na_n
    }
}
impl ::aws_types::request_id::RequestId for DescribeStorageConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeStorageConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeStorageConfigurationOutput`](crate::operation::describe_storage_configuration::DescribeStorageConfigurationOutput).
    pub fn builder() -> crate::operation::describe_storage_configuration::builders::DescribeStorageConfigurationOutputBuilder {
        crate::operation::describe_storage_configuration::builders::DescribeStorageConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DescribeStorageConfigurationOutput`](crate::operation::describe_storage_configuration::DescribeStorageConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeStorageConfigurationOutputBuilder {
    pub(crate) storage_type: ::std::option::Option<crate::types::StorageType>,
    pub(crate) multi_layer_storage: ::std::option::Option<crate::types::MultiLayerStorage>,
    pub(crate) disassociated_data_storage: ::std::option::Option<crate::types::DisassociatedDataStorageState>,
    pub(crate) retention_period: ::std::option::Option<crate::types::RetentionPeriod>,
    pub(crate) configuration_status: ::std::option::Option<crate::types::ConfigurationStatus>,
    pub(crate) last_update_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) warm_tier: ::std::option::Option<crate::types::WarmTierState>,
    pub(crate) warm_tier_retention_period: ::std::option::Option<crate::types::WarmTierRetentionPeriod>,
    pub(crate) disallow_ingest_null_na_n: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl DescribeStorageConfigurationOutputBuilder {
    /// <p>The storage tier that you specified for your data. The <code>storageType</code> parameter can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SITEWISE_DEFAULT_STORAGE</code> – IoT SiteWise saves your data into the hot tier. The hot tier is a service-managed database.</p></li>
    /// <li>
    /// <p><code>MULTI_LAYER_STORAGE</code> – IoT SiteWise saves your data in both the cold tier and the hot tier. The cold tier is a customer-managed Amazon S3 bucket.</p></li>
    /// </ul>
    /// This field is required.
    pub fn storage_type(mut self, input: crate::types::StorageType) -> Self {
        self.storage_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The storage tier that you specified for your data. The <code>storageType</code> parameter can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SITEWISE_DEFAULT_STORAGE</code> – IoT SiteWise saves your data into the hot tier. The hot tier is a service-managed database.</p></li>
    /// <li>
    /// <p><code>MULTI_LAYER_STORAGE</code> – IoT SiteWise saves your data in both the cold tier and the hot tier. The cold tier is a customer-managed Amazon S3 bucket.</p></li>
    /// </ul>
    pub fn set_storage_type(mut self, input: ::std::option::Option<crate::types::StorageType>) -> Self {
        self.storage_type = input;
        self
    }
    /// <p>The storage tier that you specified for your data. The <code>storageType</code> parameter can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SITEWISE_DEFAULT_STORAGE</code> – IoT SiteWise saves your data into the hot tier. The hot tier is a service-managed database.</p></li>
    /// <li>
    /// <p><code>MULTI_LAYER_STORAGE</code> – IoT SiteWise saves your data in both the cold tier and the hot tier. The cold tier is a customer-managed Amazon S3 bucket.</p></li>
    /// </ul>
    pub fn get_storage_type(&self) -> &::std::option::Option<crate::types::StorageType> {
        &self.storage_type
    }
    /// <p>Contains information about the storage destination.</p>
    pub fn multi_layer_storage(mut self, input: crate::types::MultiLayerStorage) -> Self {
        self.multi_layer_storage = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the storage destination.</p>
    pub fn set_multi_layer_storage(mut self, input: ::std::option::Option<crate::types::MultiLayerStorage>) -> Self {
        self.multi_layer_storage = input;
        self
    }
    /// <p>Contains information about the storage destination.</p>
    pub fn get_multi_layer_storage(&self) -> &::std::option::Option<crate::types::MultiLayerStorage> {
        &self.multi_layer_storage
    }
    /// <p>Contains the storage configuration for time series (data streams) that aren't associated with asset properties. The <code>disassociatedDataStorage</code> can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – IoT SiteWise accepts time series that aren't associated with asset properties.</p><important>
    /// <p>After the <code>disassociatedDataStorage</code> is enabled, you can't disable it.</p>
    /// </important></li>
    /// <li>
    /// <p><code>DISABLED</code> – IoT SiteWise doesn't accept time series (data streams) that aren't associated with asset properties.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/data-streams.html">Data streams</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn disassociated_data_storage(mut self, input: crate::types::DisassociatedDataStorageState) -> Self {
        self.disassociated_data_storage = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the storage configuration for time series (data streams) that aren't associated with asset properties. The <code>disassociatedDataStorage</code> can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – IoT SiteWise accepts time series that aren't associated with asset properties.</p><important>
    /// <p>After the <code>disassociatedDataStorage</code> is enabled, you can't disable it.</p>
    /// </important></li>
    /// <li>
    /// <p><code>DISABLED</code> – IoT SiteWise doesn't accept time series (data streams) that aren't associated with asset properties.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/data-streams.html">Data streams</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn set_disassociated_data_storage(mut self, input: ::std::option::Option<crate::types::DisassociatedDataStorageState>) -> Self {
        self.disassociated_data_storage = input;
        self
    }
    /// <p>Contains the storage configuration for time series (data streams) that aren't associated with asset properties. The <code>disassociatedDataStorage</code> can be one of the following values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ENABLED</code> – IoT SiteWise accepts time series that aren't associated with asset properties.</p><important>
    /// <p>After the <code>disassociatedDataStorage</code> is enabled, you can't disable it.</p>
    /// </important></li>
    /// <li>
    /// <p><code>DISABLED</code> – IoT SiteWise doesn't accept time series (data streams) that aren't associated with asset properties.</p></li>
    /// </ul>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/iot-sitewise/latest/userguide/data-streams.html">Data streams</a> in the <i>IoT SiteWise User Guide</i>.</p>
    pub fn get_disassociated_data_storage(&self) -> &::std::option::Option<crate::types::DisassociatedDataStorageState> {
        &self.disassociated_data_storage
    }
    /// <p>The number of days your data is kept in the hot tier. By default, your data is kept indefinitely in the hot tier.</p>
    pub fn retention_period(mut self, input: crate::types::RetentionPeriod) -> Self {
        self.retention_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of days your data is kept in the hot tier. By default, your data is kept indefinitely in the hot tier.</p>
    pub fn set_retention_period(mut self, input: ::std::option::Option<crate::types::RetentionPeriod>) -> Self {
        self.retention_period = input;
        self
    }
    /// <p>The number of days your data is kept in the hot tier. By default, your data is kept indefinitely in the hot tier.</p>
    pub fn get_retention_period(&self) -> &::std::option::Option<crate::types::RetentionPeriod> {
        &self.retention_period
    }
    /// <p>Contains current status information for the configuration.</p>
    /// This field is required.
    pub fn configuration_status(mut self, input: crate::types::ConfigurationStatus) -> Self {
        self.configuration_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains current status information for the configuration.</p>
    pub fn set_configuration_status(mut self, input: ::std::option::Option<crate::types::ConfigurationStatus>) -> Self {
        self.configuration_status = input;
        self
    }
    /// <p>Contains current status information for the configuration.</p>
    pub fn get_configuration_status(&self) -> &::std::option::Option<crate::types::ConfigurationStatus> {
        &self.configuration_status
    }
    /// <p>The date the storage configuration was last updated, in Unix epoch time.</p>
    pub fn last_update_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_update_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date the storage configuration was last updated, in Unix epoch time.</p>
    pub fn set_last_update_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_update_date = input;
        self
    }
    /// <p>The date the storage configuration was last updated, in Unix epoch time.</p>
    pub fn get_last_update_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_update_date
    }
    /// <p>A service managed storage tier optimized for analytical queries. It stores periodically uploaded, buffered and historical data ingested with the CreaeBulkImportJob API.</p>
    pub fn warm_tier(mut self, input: crate::types::WarmTierState) -> Self {
        self.warm_tier = ::std::option::Option::Some(input);
        self
    }
    /// <p>A service managed storage tier optimized for analytical queries. It stores periodically uploaded, buffered and historical data ingested with the CreaeBulkImportJob API.</p>
    pub fn set_warm_tier(mut self, input: ::std::option::Option<crate::types::WarmTierState>) -> Self {
        self.warm_tier = input;
        self
    }
    /// <p>A service managed storage tier optimized for analytical queries. It stores periodically uploaded, buffered and historical data ingested with the CreaeBulkImportJob API.</p>
    pub fn get_warm_tier(&self) -> &::std::option::Option<crate::types::WarmTierState> {
        &self.warm_tier
    }
    /// <p>Set this period to specify how long your data is stored in the warm tier before it is deleted. You can set this only if cold tier is enabled.</p>
    pub fn warm_tier_retention_period(mut self, input: crate::types::WarmTierRetentionPeriod) -> Self {
        self.warm_tier_retention_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set this period to specify how long your data is stored in the warm tier before it is deleted. You can set this only if cold tier is enabled.</p>
    pub fn set_warm_tier_retention_period(mut self, input: ::std::option::Option<crate::types::WarmTierRetentionPeriod>) -> Self {
        self.warm_tier_retention_period = input;
        self
    }
    /// <p>Set this period to specify how long your data is stored in the warm tier before it is deleted. You can set this only if cold tier is enabled.</p>
    pub fn get_warm_tier_retention_period(&self) -> &::std::option::Option<crate::types::WarmTierRetentionPeriod> {
        &self.warm_tier_retention_period
    }
    /// <p>Describes the configuration for ingesting NULL and NaN data. By default the feature is allowed. The feature is disallowed if the value is <code>true</code>.</p>
    pub fn disallow_ingest_null_na_n(mut self, input: bool) -> Self {
        self.disallow_ingest_null_na_n = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the configuration for ingesting NULL and NaN data. By default the feature is allowed. The feature is disallowed if the value is <code>true</code>.</p>
    pub fn set_disallow_ingest_null_na_n(mut self, input: ::std::option::Option<bool>) -> Self {
        self.disallow_ingest_null_na_n = input;
        self
    }
    /// <p>Describes the configuration for ingesting NULL and NaN data. By default the feature is allowed. The feature is disallowed if the value is <code>true</code>.</p>
    pub fn get_disallow_ingest_null_na_n(&self) -> &::std::option::Option<bool> {
        &self.disallow_ingest_null_na_n
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeStorageConfigurationOutput`](crate::operation::describe_storage_configuration::DescribeStorageConfigurationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`storage_type`](crate::operation::describe_storage_configuration::builders::DescribeStorageConfigurationOutputBuilder::storage_type)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_storage_configuration::DescribeStorageConfigurationOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_storage_configuration::DescribeStorageConfigurationOutput {
            storage_type: self.storage_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "storage_type",
                    "storage_type was not specified but it is required when building DescribeStorageConfigurationOutput",
                )
            })?,
            multi_layer_storage: self.multi_layer_storage,
            disassociated_data_storage: self.disassociated_data_storage,
            retention_period: self.retention_period,
            configuration_status: self.configuration_status,
            last_update_date: self.last_update_date,
            warm_tier: self.warm_tier,
            warm_tier_retention_period: self.warm_tier_retention_period,
            disallow_ingest_null_na_n: self.disallow_ingest_null_na_n,
            _request_id: self._request_id,
        })
    }
}
