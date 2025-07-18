// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDatasetInput {
    /// <p>The name of the project in which you want to create a dataset.</p>
    pub project_name: ::std::option::Option<::std::string::String>,
    /// <p>The type of the dataset. Specify <code>train</code> for a training dataset. Specify <code>test</code> for a test dataset.</p>
    pub dataset_type: ::std::option::Option<::std::string::String>,
    /// <p>The location of the manifest file that Amazon Lookout for Vision uses to create the dataset.</p>
    /// <p>If you don't specify <code>DatasetSource</code>, an empty dataset is created and the operation synchronously returns. Later, you can add JSON Lines by calling <code>UpdateDatasetEntries</code>.</p>
    /// <p>If you specify a value for <code>DataSource</code>, the manifest at the S3 location is validated and used to create the dataset. The call to <code>CreateDataset</code> is asynchronous and might take a while to complete. To find out the current status, Check the value of <code>Status</code> returned in a call to <code>DescribeDataset</code>.</p>
    pub dataset_source: ::std::option::Option<crate::types::DatasetSource>,
    /// <p>ClientToken is an idempotency token that ensures a call to <code>CreateDataset</code> completes only once. You choose the value to pass. For example, An issue might prevent you from getting a response from <code>CreateDataset</code>. In this case, safely retry your call to <code>CreateDataset</code> by using the same <code>ClientToken</code> parameter value.</p>
    /// <p>If you don't supply a value for <code>ClientToken</code>, the AWS SDK you are using inserts a value for you. This prevents retries after a network error from making multiple dataset creation requests. You'll need to provide your own value for other use cases.</p>
    /// <p>An error occurs if the other input parameters are not the same as in the first request. Using a different value for <code>ClientToken</code> is considered a new call to <code>CreateDataset</code>. An idempotency token is active for 8 hours.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateDatasetInput {
    /// <p>The name of the project in which you want to create a dataset.</p>
    pub fn project_name(&self) -> ::std::option::Option<&str> {
        self.project_name.as_deref()
    }
    /// <p>The type of the dataset. Specify <code>train</code> for a training dataset. Specify <code>test</code> for a test dataset.</p>
    pub fn dataset_type(&self) -> ::std::option::Option<&str> {
        self.dataset_type.as_deref()
    }
    /// <p>The location of the manifest file that Amazon Lookout for Vision uses to create the dataset.</p>
    /// <p>If you don't specify <code>DatasetSource</code>, an empty dataset is created and the operation synchronously returns. Later, you can add JSON Lines by calling <code>UpdateDatasetEntries</code>.</p>
    /// <p>If you specify a value for <code>DataSource</code>, the manifest at the S3 location is validated and used to create the dataset. The call to <code>CreateDataset</code> is asynchronous and might take a while to complete. To find out the current status, Check the value of <code>Status</code> returned in a call to <code>DescribeDataset</code>.</p>
    pub fn dataset_source(&self) -> ::std::option::Option<&crate::types::DatasetSource> {
        self.dataset_source.as_ref()
    }
    /// <p>ClientToken is an idempotency token that ensures a call to <code>CreateDataset</code> completes only once. You choose the value to pass. For example, An issue might prevent you from getting a response from <code>CreateDataset</code>. In this case, safely retry your call to <code>CreateDataset</code> by using the same <code>ClientToken</code> parameter value.</p>
    /// <p>If you don't supply a value for <code>ClientToken</code>, the AWS SDK you are using inserts a value for you. This prevents retries after a network error from making multiple dataset creation requests. You'll need to provide your own value for other use cases.</p>
    /// <p>An error occurs if the other input parameters are not the same as in the first request. Using a different value for <code>ClientToken</code> is considered a new call to <code>CreateDataset</code>. An idempotency token is active for 8 hours.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreateDatasetInput {
    /// Creates a new builder-style object to manufacture [`CreateDatasetInput`](crate::operation::create_dataset::CreateDatasetInput).
    pub fn builder() -> crate::operation::create_dataset::builders::CreateDatasetInputBuilder {
        crate::operation::create_dataset::builders::CreateDatasetInputBuilder::default()
    }
}

/// A builder for [`CreateDatasetInput`](crate::operation::create_dataset::CreateDatasetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDatasetInputBuilder {
    pub(crate) project_name: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_type: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_source: ::std::option::Option<crate::types::DatasetSource>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateDatasetInputBuilder {
    /// <p>The name of the project in which you want to create a dataset.</p>
    /// This field is required.
    pub fn project_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the project in which you want to create a dataset.</p>
    pub fn set_project_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project_name = input;
        self
    }
    /// <p>The name of the project in which you want to create a dataset.</p>
    pub fn get_project_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.project_name
    }
    /// <p>The type of the dataset. Specify <code>train</code> for a training dataset. Specify <code>test</code> for a test dataset.</p>
    /// This field is required.
    pub fn dataset_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the dataset. Specify <code>train</code> for a training dataset. Specify <code>test</code> for a test dataset.</p>
    pub fn set_dataset_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_type = input;
        self
    }
    /// <p>The type of the dataset. Specify <code>train</code> for a training dataset. Specify <code>test</code> for a test dataset.</p>
    pub fn get_dataset_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_type
    }
    /// <p>The location of the manifest file that Amazon Lookout for Vision uses to create the dataset.</p>
    /// <p>If you don't specify <code>DatasetSource</code>, an empty dataset is created and the operation synchronously returns. Later, you can add JSON Lines by calling <code>UpdateDatasetEntries</code>.</p>
    /// <p>If you specify a value for <code>DataSource</code>, the manifest at the S3 location is validated and used to create the dataset. The call to <code>CreateDataset</code> is asynchronous and might take a while to complete. To find out the current status, Check the value of <code>Status</code> returned in a call to <code>DescribeDataset</code>.</p>
    pub fn dataset_source(mut self, input: crate::types::DatasetSource) -> Self {
        self.dataset_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location of the manifest file that Amazon Lookout for Vision uses to create the dataset.</p>
    /// <p>If you don't specify <code>DatasetSource</code>, an empty dataset is created and the operation synchronously returns. Later, you can add JSON Lines by calling <code>UpdateDatasetEntries</code>.</p>
    /// <p>If you specify a value for <code>DataSource</code>, the manifest at the S3 location is validated and used to create the dataset. The call to <code>CreateDataset</code> is asynchronous and might take a while to complete. To find out the current status, Check the value of <code>Status</code> returned in a call to <code>DescribeDataset</code>.</p>
    pub fn set_dataset_source(mut self, input: ::std::option::Option<crate::types::DatasetSource>) -> Self {
        self.dataset_source = input;
        self
    }
    /// <p>The location of the manifest file that Amazon Lookout for Vision uses to create the dataset.</p>
    /// <p>If you don't specify <code>DatasetSource</code>, an empty dataset is created and the operation synchronously returns. Later, you can add JSON Lines by calling <code>UpdateDatasetEntries</code>.</p>
    /// <p>If you specify a value for <code>DataSource</code>, the manifest at the S3 location is validated and used to create the dataset. The call to <code>CreateDataset</code> is asynchronous and might take a while to complete. To find out the current status, Check the value of <code>Status</code> returned in a call to <code>DescribeDataset</code>.</p>
    pub fn get_dataset_source(&self) -> &::std::option::Option<crate::types::DatasetSource> {
        &self.dataset_source
    }
    /// <p>ClientToken is an idempotency token that ensures a call to <code>CreateDataset</code> completes only once. You choose the value to pass. For example, An issue might prevent you from getting a response from <code>CreateDataset</code>. In this case, safely retry your call to <code>CreateDataset</code> by using the same <code>ClientToken</code> parameter value.</p>
    /// <p>If you don't supply a value for <code>ClientToken</code>, the AWS SDK you are using inserts a value for you. This prevents retries after a network error from making multiple dataset creation requests. You'll need to provide your own value for other use cases.</p>
    /// <p>An error occurs if the other input parameters are not the same as in the first request. Using a different value for <code>ClientToken</code> is considered a new call to <code>CreateDataset</code>. An idempotency token is active for 8 hours.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ClientToken is an idempotency token that ensures a call to <code>CreateDataset</code> completes only once. You choose the value to pass. For example, An issue might prevent you from getting a response from <code>CreateDataset</code>. In this case, safely retry your call to <code>CreateDataset</code> by using the same <code>ClientToken</code> parameter value.</p>
    /// <p>If you don't supply a value for <code>ClientToken</code>, the AWS SDK you are using inserts a value for you. This prevents retries after a network error from making multiple dataset creation requests. You'll need to provide your own value for other use cases.</p>
    /// <p>An error occurs if the other input parameters are not the same as in the first request. Using a different value for <code>ClientToken</code> is considered a new call to <code>CreateDataset</code>. An idempotency token is active for 8 hours.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>ClientToken is an idempotency token that ensures a call to <code>CreateDataset</code> completes only once. You choose the value to pass. For example, An issue might prevent you from getting a response from <code>CreateDataset</code>. In this case, safely retry your call to <code>CreateDataset</code> by using the same <code>ClientToken</code> parameter value.</p>
    /// <p>If you don't supply a value for <code>ClientToken</code>, the AWS SDK you are using inserts a value for you. This prevents retries after a network error from making multiple dataset creation requests. You'll need to provide your own value for other use cases.</p>
    /// <p>An error occurs if the other input parameters are not the same as in the first request. Using a different value for <code>ClientToken</code> is considered a new call to <code>CreateDataset</code>. An idempotency token is active for 8 hours.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateDatasetInput`](crate::operation::create_dataset::CreateDatasetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_dataset::CreateDatasetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_dataset::CreateDatasetInput {
            project_name: self.project_name,
            dataset_type: self.dataset_type,
            dataset_source: self.dataset_source,
            client_token: self.client_token,
        })
    }
}
