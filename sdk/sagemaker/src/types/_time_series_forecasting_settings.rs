// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Time series forecast settings for the SageMaker Canvas application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimeSeriesForecastingSettings {
    /// <p>Describes whether time series forecasting is enabled or disabled in the Canvas application.</p>
    pub status: ::std::option::Option<crate::types::FeatureStatus>,
    /// <p>The IAM role that Canvas passes to Amazon Forecast for time series forecasting. By default, Canvas uses the execution role specified in the <code>UserProfile</code> that launches the Canvas application. If an execution role is not specified in the <code>UserProfile</code>, Canvas uses the execution role specified in the Domain that owns the <code>UserProfile</code>. To allow time series forecasting, this IAM role should have the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol-canvas.html#security-iam-awsmanpol-AmazonSageMakerCanvasForecastAccess"> AmazonSageMakerCanvasForecastAccess</a> policy attached and <code>forecast.amazonaws.com</code> added in the trust relationship as a service principal.</p>
    pub amazon_forecast_role_arn: ::std::option::Option<::std::string::String>,
}
impl TimeSeriesForecastingSettings {
    /// <p>Describes whether time series forecasting is enabled or disabled in the Canvas application.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::FeatureStatus> {
        self.status.as_ref()
    }
    /// <p>The IAM role that Canvas passes to Amazon Forecast for time series forecasting. By default, Canvas uses the execution role specified in the <code>UserProfile</code> that launches the Canvas application. If an execution role is not specified in the <code>UserProfile</code>, Canvas uses the execution role specified in the Domain that owns the <code>UserProfile</code>. To allow time series forecasting, this IAM role should have the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol-canvas.html#security-iam-awsmanpol-AmazonSageMakerCanvasForecastAccess"> AmazonSageMakerCanvasForecastAccess</a> policy attached and <code>forecast.amazonaws.com</code> added in the trust relationship as a service principal.</p>
    pub fn amazon_forecast_role_arn(&self) -> ::std::option::Option<&str> {
        self.amazon_forecast_role_arn.as_deref()
    }
}
impl TimeSeriesForecastingSettings {
    /// Creates a new builder-style object to manufacture [`TimeSeriesForecastingSettings`](crate::types::TimeSeriesForecastingSettings).
    pub fn builder() -> crate::types::builders::TimeSeriesForecastingSettingsBuilder {
        crate::types::builders::TimeSeriesForecastingSettingsBuilder::default()
    }
}

/// A builder for [`TimeSeriesForecastingSettings`](crate::types::TimeSeriesForecastingSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimeSeriesForecastingSettingsBuilder {
    pub(crate) status: ::std::option::Option<crate::types::FeatureStatus>,
    pub(crate) amazon_forecast_role_arn: ::std::option::Option<::std::string::String>,
}
impl TimeSeriesForecastingSettingsBuilder {
    /// <p>Describes whether time series forecasting is enabled or disabled in the Canvas application.</p>
    pub fn status(mut self, input: crate::types::FeatureStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes whether time series forecasting is enabled or disabled in the Canvas application.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::FeatureStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Describes whether time series forecasting is enabled or disabled in the Canvas application.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::FeatureStatus> {
        &self.status
    }
    /// <p>The IAM role that Canvas passes to Amazon Forecast for time series forecasting. By default, Canvas uses the execution role specified in the <code>UserProfile</code> that launches the Canvas application. If an execution role is not specified in the <code>UserProfile</code>, Canvas uses the execution role specified in the Domain that owns the <code>UserProfile</code>. To allow time series forecasting, this IAM role should have the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol-canvas.html#security-iam-awsmanpol-AmazonSageMakerCanvasForecastAccess"> AmazonSageMakerCanvasForecastAccess</a> policy attached and <code>forecast.amazonaws.com</code> added in the trust relationship as a service principal.</p>
    pub fn amazon_forecast_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.amazon_forecast_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role that Canvas passes to Amazon Forecast for time series forecasting. By default, Canvas uses the execution role specified in the <code>UserProfile</code> that launches the Canvas application. If an execution role is not specified in the <code>UserProfile</code>, Canvas uses the execution role specified in the Domain that owns the <code>UserProfile</code>. To allow time series forecasting, this IAM role should have the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol-canvas.html#security-iam-awsmanpol-AmazonSageMakerCanvasForecastAccess"> AmazonSageMakerCanvasForecastAccess</a> policy attached and <code>forecast.amazonaws.com</code> added in the trust relationship as a service principal.</p>
    pub fn set_amazon_forecast_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.amazon_forecast_role_arn = input;
        self
    }
    /// <p>The IAM role that Canvas passes to Amazon Forecast for time series forecasting. By default, Canvas uses the execution role specified in the <code>UserProfile</code> that launches the Canvas application. If an execution role is not specified in the <code>UserProfile</code>, Canvas uses the execution role specified in the Domain that owns the <code>UserProfile</code>. To allow time series forecasting, this IAM role should have the <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol-canvas.html#security-iam-awsmanpol-AmazonSageMakerCanvasForecastAccess"> AmazonSageMakerCanvasForecastAccess</a> policy attached and <code>forecast.amazonaws.com</code> added in the trust relationship as a service principal.</p>
    pub fn get_amazon_forecast_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.amazon_forecast_role_arn
    }
    /// Consumes the builder and constructs a [`TimeSeriesForecastingSettings`](crate::types::TimeSeriesForecastingSettings).
    pub fn build(self) -> crate::types::TimeSeriesForecastingSettings {
        crate::types::TimeSeriesForecastingSettings {
            status: self.status,
            amazon_forecast_role_arn: self.amazon_forecast_role_arn,
        }
    }
}
