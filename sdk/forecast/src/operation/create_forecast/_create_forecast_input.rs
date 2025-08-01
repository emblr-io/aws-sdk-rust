// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateForecastInput {
    /// <p>A name for the forecast.</p>
    pub forecast_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the predictor to use to generate the forecast.</p>
    pub predictor_arn: ::std::option::Option<::std::string::String>,
    /// <p>The quantiles at which probabilistic forecasts are generated. <b>You can currently specify up to 5 quantiles per forecast</b>. Accepted values include <code>0.01 to 0.99</code> (increments of .01 only) and <code>mean</code>. The mean forecast is different from the median (0.50) when the distribution is not symmetric (for example, Beta and Negative Binomial).</p>
    /// <p>The default quantiles are the quantiles you specified during predictor creation. If you didn't specify quantiles, the default values are <code>\["0.1", "0.5", "0.9"\]</code>.</p>
    pub forecast_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The optional metadata that you apply to the forecast to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
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
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>Defines the set of time series that are used to create the forecasts in a <code>TimeSeriesIdentifiers</code> object.</p>
    /// <p>The <code>TimeSeriesIdentifiers</code> object needs the following information:</p>
    /// <ul>
    /// <li>
    /// <p><code>DataSource</code></p></li>
    /// <li>
    /// <p><code>Format</code></p></li>
    /// <li>
    /// <p><code>Schema</code></p></li>
    /// </ul>
    pub time_series_selector: ::std::option::Option<crate::types::TimeSeriesSelector>,
}
impl CreateForecastInput {
    /// <p>A name for the forecast.</p>
    pub fn forecast_name(&self) -> ::std::option::Option<&str> {
        self.forecast_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the predictor to use to generate the forecast.</p>
    pub fn predictor_arn(&self) -> ::std::option::Option<&str> {
        self.predictor_arn.as_deref()
    }
    /// <p>The quantiles at which probabilistic forecasts are generated. <b>You can currently specify up to 5 quantiles per forecast</b>. Accepted values include <code>0.01 to 0.99</code> (increments of .01 only) and <code>mean</code>. The mean forecast is different from the median (0.50) when the distribution is not symmetric (for example, Beta and Negative Binomial).</p>
    /// <p>The default quantiles are the quantiles you specified during predictor creation. If you didn't specify quantiles, the default values are <code>\["0.1", "0.5", "0.9"\]</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.forecast_types.is_none()`.
    pub fn forecast_types(&self) -> &[::std::string::String] {
        self.forecast_types.as_deref().unwrap_or_default()
    }
    /// <p>The optional metadata that you apply to the forecast to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
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
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Defines the set of time series that are used to create the forecasts in a <code>TimeSeriesIdentifiers</code> object.</p>
    /// <p>The <code>TimeSeriesIdentifiers</code> object needs the following information:</p>
    /// <ul>
    /// <li>
    /// <p><code>DataSource</code></p></li>
    /// <li>
    /// <p><code>Format</code></p></li>
    /// <li>
    /// <p><code>Schema</code></p></li>
    /// </ul>
    pub fn time_series_selector(&self) -> ::std::option::Option<&crate::types::TimeSeriesSelector> {
        self.time_series_selector.as_ref()
    }
}
impl CreateForecastInput {
    /// Creates a new builder-style object to manufacture [`CreateForecastInput`](crate::operation::create_forecast::CreateForecastInput).
    pub fn builder() -> crate::operation::create_forecast::builders::CreateForecastInputBuilder {
        crate::operation::create_forecast::builders::CreateForecastInputBuilder::default()
    }
}

/// A builder for [`CreateForecastInput`](crate::operation::create_forecast::CreateForecastInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateForecastInputBuilder {
    pub(crate) forecast_name: ::std::option::Option<::std::string::String>,
    pub(crate) predictor_arn: ::std::option::Option<::std::string::String>,
    pub(crate) forecast_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) time_series_selector: ::std::option::Option<crate::types::TimeSeriesSelector>,
}
impl CreateForecastInputBuilder {
    /// <p>A name for the forecast.</p>
    /// This field is required.
    pub fn forecast_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.forecast_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the forecast.</p>
    pub fn set_forecast_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.forecast_name = input;
        self
    }
    /// <p>A name for the forecast.</p>
    pub fn get_forecast_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.forecast_name
    }
    /// <p>The Amazon Resource Name (ARN) of the predictor to use to generate the forecast.</p>
    /// This field is required.
    pub fn predictor_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.predictor_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the predictor to use to generate the forecast.</p>
    pub fn set_predictor_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.predictor_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the predictor to use to generate the forecast.</p>
    pub fn get_predictor_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.predictor_arn
    }
    /// Appends an item to `forecast_types`.
    ///
    /// To override the contents of this collection use [`set_forecast_types`](Self::set_forecast_types).
    ///
    /// <p>The quantiles at which probabilistic forecasts are generated. <b>You can currently specify up to 5 quantiles per forecast</b>. Accepted values include <code>0.01 to 0.99</code> (increments of .01 only) and <code>mean</code>. The mean forecast is different from the median (0.50) when the distribution is not symmetric (for example, Beta and Negative Binomial).</p>
    /// <p>The default quantiles are the quantiles you specified during predictor creation. If you didn't specify quantiles, the default values are <code>\["0.1", "0.5", "0.9"\]</code>.</p>
    pub fn forecast_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.forecast_types.unwrap_or_default();
        v.push(input.into());
        self.forecast_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The quantiles at which probabilistic forecasts are generated. <b>You can currently specify up to 5 quantiles per forecast</b>. Accepted values include <code>0.01 to 0.99</code> (increments of .01 only) and <code>mean</code>. The mean forecast is different from the median (0.50) when the distribution is not symmetric (for example, Beta and Negative Binomial).</p>
    /// <p>The default quantiles are the quantiles you specified during predictor creation. If you didn't specify quantiles, the default values are <code>\["0.1", "0.5", "0.9"\]</code>.</p>
    pub fn set_forecast_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.forecast_types = input;
        self
    }
    /// <p>The quantiles at which probabilistic forecasts are generated. <b>You can currently specify up to 5 quantiles per forecast</b>. Accepted values include <code>0.01 to 0.99</code> (increments of .01 only) and <code>mean</code>. The mean forecast is different from the median (0.50) when the distribution is not symmetric (for example, Beta and Negative Binomial).</p>
    /// <p>The default quantiles are the quantiles you specified during predictor creation. If you didn't specify quantiles, the default values are <code>\["0.1", "0.5", "0.9"\]</code>.</p>
    pub fn get_forecast_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.forecast_types
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The optional metadata that you apply to the forecast to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
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
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The optional metadata that you apply to the forecast to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
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
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The optional metadata that you apply to the forecast to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define.</p>
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
    /// <p>Do not use <code>aws:</code>, <code>AWS:</code>, or any upper or lowercase combination of such as a prefix for keys as it is reserved for Amazon Web Services use. You cannot edit or delete tag keys with this prefix. Values can have this prefix. If a tag value has <code>aws</code> as its prefix but the key does not, then Forecast considers it to be a user tag and will count against the limit of 50 tags. Tags with only the key prefix of <code>aws</code> do not count against your tags per resource limit.</p></li>
    /// </ul>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>Defines the set of time series that are used to create the forecasts in a <code>TimeSeriesIdentifiers</code> object.</p>
    /// <p>The <code>TimeSeriesIdentifiers</code> object needs the following information:</p>
    /// <ul>
    /// <li>
    /// <p><code>DataSource</code></p></li>
    /// <li>
    /// <p><code>Format</code></p></li>
    /// <li>
    /// <p><code>Schema</code></p></li>
    /// </ul>
    pub fn time_series_selector(mut self, input: crate::types::TimeSeriesSelector) -> Self {
        self.time_series_selector = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the set of time series that are used to create the forecasts in a <code>TimeSeriesIdentifiers</code> object.</p>
    /// <p>The <code>TimeSeriesIdentifiers</code> object needs the following information:</p>
    /// <ul>
    /// <li>
    /// <p><code>DataSource</code></p></li>
    /// <li>
    /// <p><code>Format</code></p></li>
    /// <li>
    /// <p><code>Schema</code></p></li>
    /// </ul>
    pub fn set_time_series_selector(mut self, input: ::std::option::Option<crate::types::TimeSeriesSelector>) -> Self {
        self.time_series_selector = input;
        self
    }
    /// <p>Defines the set of time series that are used to create the forecasts in a <code>TimeSeriesIdentifiers</code> object.</p>
    /// <p>The <code>TimeSeriesIdentifiers</code> object needs the following information:</p>
    /// <ul>
    /// <li>
    /// <p><code>DataSource</code></p></li>
    /// <li>
    /// <p><code>Format</code></p></li>
    /// <li>
    /// <p><code>Schema</code></p></li>
    /// </ul>
    pub fn get_time_series_selector(&self) -> &::std::option::Option<crate::types::TimeSeriesSelector> {
        &self.time_series_selector
    }
    /// Consumes the builder and constructs a [`CreateForecastInput`](crate::operation::create_forecast::CreateForecastInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_forecast::CreateForecastInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_forecast::CreateForecastInput {
            forecast_name: self.forecast_name,
            predictor_arn: self.predictor_arn,
            forecast_types: self.forecast_types,
            tags: self.tags,
            time_series_selector: self.time_series_selector,
        })
    }
}
