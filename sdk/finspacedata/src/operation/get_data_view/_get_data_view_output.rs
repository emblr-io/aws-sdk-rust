// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Response from retrieving a dataview, which includes details on the target database and table name
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDataViewOutput {
    /// <p>Flag to indicate Dataview should be updated automatically.</p>
    pub auto_update: bool,
    /// <p>Ordered set of column names used to partition data.</p>
    pub partition_columns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The unique identifier for the Dataset used in the Dataview.</p>
    pub dataset_id: ::std::option::Option<::std::string::String>,
    /// <p>Time range to use for the Dataview. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub as_of_timestamp: ::std::option::Option<i64>,
    /// <p>Information about an error that occurred for the Dataview.</p>
    pub error_info: ::std::option::Option<crate::types::DataViewErrorInfo>,
    /// <p>The last time that a Dataview was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub last_modified_time: i64,
    /// <p>The timestamp at which the Dataview was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub create_time: i64,
    /// <p>Columns to be used for sorting the data.</p>
    pub sort_columns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The unique identifier for the Dataview.</p>
    pub data_view_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN identifier of the Dataview.</p>
    pub data_view_arn: ::std::option::Option<::std::string::String>,
    /// <p>Options that define the destination type for the Dataview.</p>
    pub destination_type_params: ::std::option::Option<crate::types::DataViewDestinationTypeParams>,
    /// <p>The status of a Dataview creation.</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> – Dataview creation is running.</p></li>
    /// <li>
    /// <p><code>STARTING</code> – Dataview creation is starting.</p></li>
    /// <li>
    /// <p><code>FAILED</code> – Dataview creation has failed.</p></li>
    /// <li>
    /// <p><code>CANCELLED</code> – Dataview creation has been cancelled.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code> – Dataview creation has timed out.</p></li>
    /// <li>
    /// <p><code>SUCCESS</code> – Dataview creation has succeeded.</p></li>
    /// <li>
    /// <p><code>PENDING</code> – Dataview creation is pending.</p></li>
    /// <li>
    /// <p><code>FAILED_CLEANUP_FAILED</code> – Dataview creation failed and resource cleanup failed.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::DataViewStatus>,
    _request_id: Option<String>,
}
impl GetDataViewOutput {
    /// <p>Flag to indicate Dataview should be updated automatically.</p>
    pub fn auto_update(&self) -> bool {
        self.auto_update
    }
    /// <p>Ordered set of column names used to partition data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.partition_columns.is_none()`.
    pub fn partition_columns(&self) -> &[::std::string::String] {
        self.partition_columns.as_deref().unwrap_or_default()
    }
    /// <p>The unique identifier for the Dataset used in the Dataview.</p>
    pub fn dataset_id(&self) -> ::std::option::Option<&str> {
        self.dataset_id.as_deref()
    }
    /// <p>Time range to use for the Dataview. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn as_of_timestamp(&self) -> ::std::option::Option<i64> {
        self.as_of_timestamp
    }
    /// <p>Information about an error that occurred for the Dataview.</p>
    pub fn error_info(&self) -> ::std::option::Option<&crate::types::DataViewErrorInfo> {
        self.error_info.as_ref()
    }
    /// <p>The last time that a Dataview was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn last_modified_time(&self) -> i64 {
        self.last_modified_time
    }
    /// <p>The timestamp at which the Dataview was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn create_time(&self) -> i64 {
        self.create_time
    }
    /// <p>Columns to be used for sorting the data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sort_columns.is_none()`.
    pub fn sort_columns(&self) -> &[::std::string::String] {
        self.sort_columns.as_deref().unwrap_or_default()
    }
    /// <p>The unique identifier for the Dataview.</p>
    pub fn data_view_id(&self) -> ::std::option::Option<&str> {
        self.data_view_id.as_deref()
    }
    /// <p>The ARN identifier of the Dataview.</p>
    pub fn data_view_arn(&self) -> ::std::option::Option<&str> {
        self.data_view_arn.as_deref()
    }
    /// <p>Options that define the destination type for the Dataview.</p>
    pub fn destination_type_params(&self) -> ::std::option::Option<&crate::types::DataViewDestinationTypeParams> {
        self.destination_type_params.as_ref()
    }
    /// <p>The status of a Dataview creation.</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> – Dataview creation is running.</p></li>
    /// <li>
    /// <p><code>STARTING</code> – Dataview creation is starting.</p></li>
    /// <li>
    /// <p><code>FAILED</code> – Dataview creation has failed.</p></li>
    /// <li>
    /// <p><code>CANCELLED</code> – Dataview creation has been cancelled.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code> – Dataview creation has timed out.</p></li>
    /// <li>
    /// <p><code>SUCCESS</code> – Dataview creation has succeeded.</p></li>
    /// <li>
    /// <p><code>PENDING</code> – Dataview creation is pending.</p></li>
    /// <li>
    /// <p><code>FAILED_CLEANUP_FAILED</code> – Dataview creation failed and resource cleanup failed.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DataViewStatus> {
        self.status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetDataViewOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDataViewOutput {
    /// Creates a new builder-style object to manufacture [`GetDataViewOutput`](crate::operation::get_data_view::GetDataViewOutput).
    pub fn builder() -> crate::operation::get_data_view::builders::GetDataViewOutputBuilder {
        crate::operation::get_data_view::builders::GetDataViewOutputBuilder::default()
    }
}

/// A builder for [`GetDataViewOutput`](crate::operation::get_data_view::GetDataViewOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDataViewOutputBuilder {
    pub(crate) auto_update: ::std::option::Option<bool>,
    pub(crate) partition_columns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) dataset_id: ::std::option::Option<::std::string::String>,
    pub(crate) as_of_timestamp: ::std::option::Option<i64>,
    pub(crate) error_info: ::std::option::Option<crate::types::DataViewErrorInfo>,
    pub(crate) last_modified_time: ::std::option::Option<i64>,
    pub(crate) create_time: ::std::option::Option<i64>,
    pub(crate) sort_columns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) data_view_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_view_arn: ::std::option::Option<::std::string::String>,
    pub(crate) destination_type_params: ::std::option::Option<crate::types::DataViewDestinationTypeParams>,
    pub(crate) status: ::std::option::Option<crate::types::DataViewStatus>,
    _request_id: Option<String>,
}
impl GetDataViewOutputBuilder {
    /// <p>Flag to indicate Dataview should be updated automatically.</p>
    pub fn auto_update(mut self, input: bool) -> Self {
        self.auto_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Flag to indicate Dataview should be updated automatically.</p>
    pub fn set_auto_update(mut self, input: ::std::option::Option<bool>) -> Self {
        self.auto_update = input;
        self
    }
    /// <p>Flag to indicate Dataview should be updated automatically.</p>
    pub fn get_auto_update(&self) -> &::std::option::Option<bool> {
        &self.auto_update
    }
    /// Appends an item to `partition_columns`.
    ///
    /// To override the contents of this collection use [`set_partition_columns`](Self::set_partition_columns).
    ///
    /// <p>Ordered set of column names used to partition data.</p>
    pub fn partition_columns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.partition_columns.unwrap_or_default();
        v.push(input.into());
        self.partition_columns = ::std::option::Option::Some(v);
        self
    }
    /// <p>Ordered set of column names used to partition data.</p>
    pub fn set_partition_columns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.partition_columns = input;
        self
    }
    /// <p>Ordered set of column names used to partition data.</p>
    pub fn get_partition_columns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.partition_columns
    }
    /// <p>The unique identifier for the Dataset used in the Dataview.</p>
    pub fn dataset_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the Dataset used in the Dataview.</p>
    pub fn set_dataset_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_id = input;
        self
    }
    /// <p>The unique identifier for the Dataset used in the Dataview.</p>
    pub fn get_dataset_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_id
    }
    /// <p>Time range to use for the Dataview. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn as_of_timestamp(mut self, input: i64) -> Self {
        self.as_of_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time range to use for the Dataview. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn set_as_of_timestamp(mut self, input: ::std::option::Option<i64>) -> Self {
        self.as_of_timestamp = input;
        self
    }
    /// <p>Time range to use for the Dataview. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn get_as_of_timestamp(&self) -> &::std::option::Option<i64> {
        &self.as_of_timestamp
    }
    /// <p>Information about an error that occurred for the Dataview.</p>
    pub fn error_info(mut self, input: crate::types::DataViewErrorInfo) -> Self {
        self.error_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about an error that occurred for the Dataview.</p>
    pub fn set_error_info(mut self, input: ::std::option::Option<crate::types::DataViewErrorInfo>) -> Self {
        self.error_info = input;
        self
    }
    /// <p>Information about an error that occurred for the Dataview.</p>
    pub fn get_error_info(&self) -> &::std::option::Option<crate::types::DataViewErrorInfo> {
        &self.error_info
    }
    /// <p>The last time that a Dataview was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn last_modified_time(mut self, input: i64) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time that a Dataview was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The last time that a Dataview was modified. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<i64> {
        &self.last_modified_time
    }
    /// <p>The timestamp at which the Dataview was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn create_time(mut self, input: i64) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the Dataview was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<i64>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The timestamp at which the Dataview was created in FinSpace. The value is determined as epoch time in milliseconds. For example, the value for Monday, November 1, 2021 12:00:00 PM UTC is specified as 1635768000000.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<i64> {
        &self.create_time
    }
    /// Appends an item to `sort_columns`.
    ///
    /// To override the contents of this collection use [`set_sort_columns`](Self::set_sort_columns).
    ///
    /// <p>Columns to be used for sorting the data.</p>
    pub fn sort_columns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.sort_columns.unwrap_or_default();
        v.push(input.into());
        self.sort_columns = ::std::option::Option::Some(v);
        self
    }
    /// <p>Columns to be used for sorting the data.</p>
    pub fn set_sort_columns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.sort_columns = input;
        self
    }
    /// <p>Columns to be used for sorting the data.</p>
    pub fn get_sort_columns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.sort_columns
    }
    /// <p>The unique identifier for the Dataview.</p>
    pub fn data_view_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_view_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the Dataview.</p>
    pub fn set_data_view_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_view_id = input;
        self
    }
    /// <p>The unique identifier for the Dataview.</p>
    pub fn get_data_view_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_view_id
    }
    /// <p>The ARN identifier of the Dataview.</p>
    pub fn data_view_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_view_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN identifier of the Dataview.</p>
    pub fn set_data_view_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_view_arn = input;
        self
    }
    /// <p>The ARN identifier of the Dataview.</p>
    pub fn get_data_view_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_view_arn
    }
    /// <p>Options that define the destination type for the Dataview.</p>
    pub fn destination_type_params(mut self, input: crate::types::DataViewDestinationTypeParams) -> Self {
        self.destination_type_params = ::std::option::Option::Some(input);
        self
    }
    /// <p>Options that define the destination type for the Dataview.</p>
    pub fn set_destination_type_params(mut self, input: ::std::option::Option<crate::types::DataViewDestinationTypeParams>) -> Self {
        self.destination_type_params = input;
        self
    }
    /// <p>Options that define the destination type for the Dataview.</p>
    pub fn get_destination_type_params(&self) -> &::std::option::Option<crate::types::DataViewDestinationTypeParams> {
        &self.destination_type_params
    }
    /// <p>The status of a Dataview creation.</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> – Dataview creation is running.</p></li>
    /// <li>
    /// <p><code>STARTING</code> – Dataview creation is starting.</p></li>
    /// <li>
    /// <p><code>FAILED</code> – Dataview creation has failed.</p></li>
    /// <li>
    /// <p><code>CANCELLED</code> – Dataview creation has been cancelled.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code> – Dataview creation has timed out.</p></li>
    /// <li>
    /// <p><code>SUCCESS</code> – Dataview creation has succeeded.</p></li>
    /// <li>
    /// <p><code>PENDING</code> – Dataview creation is pending.</p></li>
    /// <li>
    /// <p><code>FAILED_CLEANUP_FAILED</code> – Dataview creation failed and resource cleanup failed.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::DataViewStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of a Dataview creation.</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> – Dataview creation is running.</p></li>
    /// <li>
    /// <p><code>STARTING</code> – Dataview creation is starting.</p></li>
    /// <li>
    /// <p><code>FAILED</code> – Dataview creation has failed.</p></li>
    /// <li>
    /// <p><code>CANCELLED</code> – Dataview creation has been cancelled.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code> – Dataview creation has timed out.</p></li>
    /// <li>
    /// <p><code>SUCCESS</code> – Dataview creation has succeeded.</p></li>
    /// <li>
    /// <p><code>PENDING</code> – Dataview creation is pending.</p></li>
    /// <li>
    /// <p><code>FAILED_CLEANUP_FAILED</code> – Dataview creation failed and resource cleanup failed.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DataViewStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of a Dataview creation.</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> – Dataview creation is running.</p></li>
    /// <li>
    /// <p><code>STARTING</code> – Dataview creation is starting.</p></li>
    /// <li>
    /// <p><code>FAILED</code> – Dataview creation has failed.</p></li>
    /// <li>
    /// <p><code>CANCELLED</code> – Dataview creation has been cancelled.</p></li>
    /// <li>
    /// <p><code>TIMEOUT</code> – Dataview creation has timed out.</p></li>
    /// <li>
    /// <p><code>SUCCESS</code> – Dataview creation has succeeded.</p></li>
    /// <li>
    /// <p><code>PENDING</code> – Dataview creation is pending.</p></li>
    /// <li>
    /// <p><code>FAILED_CLEANUP_FAILED</code> – Dataview creation failed and resource cleanup failed.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DataViewStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDataViewOutput`](crate::operation::get_data_view::GetDataViewOutput).
    pub fn build(self) -> crate::operation::get_data_view::GetDataViewOutput {
        crate::operation::get_data_view::GetDataViewOutput {
            auto_update: self.auto_update.unwrap_or_default(),
            partition_columns: self.partition_columns,
            dataset_id: self.dataset_id,
            as_of_timestamp: self.as_of_timestamp,
            error_info: self.error_info,
            last_modified_time: self.last_modified_time.unwrap_or_default(),
            create_time: self.create_time.unwrap_or_default(),
            sort_columns: self.sort_columns,
            data_view_id: self.data_view_id,
            data_view_arn: self.data_view_arn,
            destination_type_params: self.destination_type_params,
            status: self.status,
            _request_id: self._request_id,
        }
    }
}
