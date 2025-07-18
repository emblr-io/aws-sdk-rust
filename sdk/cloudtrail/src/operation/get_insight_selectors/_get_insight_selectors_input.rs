// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInsightSelectorsInput {
    /// <p>Specifies the name of the trail or trail ARN. If you specify a trail name, the string must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-)</p></li>
    /// <li>
    /// <p>Start with a letter or number, and end with a letter or number</p></li>
    /// <li>
    /// <p>Be between 3 and 128 characters</p></li>
    /// <li>
    /// <p>Have no adjacent periods, underscores or dashes. Names like <code>my-_namespace</code> and <code>my--namespace</code> are not valid.</p></li>
    /// <li>
    /// <p>Not be in IP address format (for example, 192.168.5.4)</p></li>
    /// </ul>
    /// <p>If you specify a trail ARN, it must be in the format:</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    /// <p>You cannot use this parameter with the <code>EventDataStore</code> parameter.</p>
    pub trail_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the ARN (or ID suffix of the ARN) of the event data store for which you want to get Insights selectors.</p>
    /// <p>You cannot use this parameter with the <code>TrailName</code> parameter.</p>
    pub event_data_store: ::std::option::Option<::std::string::String>,
}
impl GetInsightSelectorsInput {
    /// <p>Specifies the name of the trail or trail ARN. If you specify a trail name, the string must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-)</p></li>
    /// <li>
    /// <p>Start with a letter or number, and end with a letter or number</p></li>
    /// <li>
    /// <p>Be between 3 and 128 characters</p></li>
    /// <li>
    /// <p>Have no adjacent periods, underscores or dashes. Names like <code>my-_namespace</code> and <code>my--namespace</code> are not valid.</p></li>
    /// <li>
    /// <p>Not be in IP address format (for example, 192.168.5.4)</p></li>
    /// </ul>
    /// <p>If you specify a trail ARN, it must be in the format:</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    /// <p>You cannot use this parameter with the <code>EventDataStore</code> parameter.</p>
    pub fn trail_name(&self) -> ::std::option::Option<&str> {
        self.trail_name.as_deref()
    }
    /// <p>Specifies the ARN (or ID suffix of the ARN) of the event data store for which you want to get Insights selectors.</p>
    /// <p>You cannot use this parameter with the <code>TrailName</code> parameter.</p>
    pub fn event_data_store(&self) -> ::std::option::Option<&str> {
        self.event_data_store.as_deref()
    }
}
impl GetInsightSelectorsInput {
    /// Creates a new builder-style object to manufacture [`GetInsightSelectorsInput`](crate::operation::get_insight_selectors::GetInsightSelectorsInput).
    pub fn builder() -> crate::operation::get_insight_selectors::builders::GetInsightSelectorsInputBuilder {
        crate::operation::get_insight_selectors::builders::GetInsightSelectorsInputBuilder::default()
    }
}

/// A builder for [`GetInsightSelectorsInput`](crate::operation::get_insight_selectors::GetInsightSelectorsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetInsightSelectorsInputBuilder {
    pub(crate) trail_name: ::std::option::Option<::std::string::String>,
    pub(crate) event_data_store: ::std::option::Option<::std::string::String>,
}
impl GetInsightSelectorsInputBuilder {
    /// <p>Specifies the name of the trail or trail ARN. If you specify a trail name, the string must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-)</p></li>
    /// <li>
    /// <p>Start with a letter or number, and end with a letter or number</p></li>
    /// <li>
    /// <p>Be between 3 and 128 characters</p></li>
    /// <li>
    /// <p>Have no adjacent periods, underscores or dashes. Names like <code>my-_namespace</code> and <code>my--namespace</code> are not valid.</p></li>
    /// <li>
    /// <p>Not be in IP address format (for example, 192.168.5.4)</p></li>
    /// </ul>
    /// <p>If you specify a trail ARN, it must be in the format:</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    /// <p>You cannot use this parameter with the <code>EventDataStore</code> parameter.</p>
    pub fn trail_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.trail_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the name of the trail or trail ARN. If you specify a trail name, the string must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-)</p></li>
    /// <li>
    /// <p>Start with a letter or number, and end with a letter or number</p></li>
    /// <li>
    /// <p>Be between 3 and 128 characters</p></li>
    /// <li>
    /// <p>Have no adjacent periods, underscores or dashes. Names like <code>my-_namespace</code> and <code>my--namespace</code> are not valid.</p></li>
    /// <li>
    /// <p>Not be in IP address format (for example, 192.168.5.4)</p></li>
    /// </ul>
    /// <p>If you specify a trail ARN, it must be in the format:</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    /// <p>You cannot use this parameter with the <code>EventDataStore</code> parameter.</p>
    pub fn set_trail_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.trail_name = input;
        self
    }
    /// <p>Specifies the name of the trail or trail ARN. If you specify a trail name, the string must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), periods (.), underscores (_), or dashes (-)</p></li>
    /// <li>
    /// <p>Start with a letter or number, and end with a letter or number</p></li>
    /// <li>
    /// <p>Be between 3 and 128 characters</p></li>
    /// <li>
    /// <p>Have no adjacent periods, underscores or dashes. Names like <code>my-_namespace</code> and <code>my--namespace</code> are not valid.</p></li>
    /// <li>
    /// <p>Not be in IP address format (for example, 192.168.5.4)</p></li>
    /// </ul>
    /// <p>If you specify a trail ARN, it must be in the format:</p>
    /// <p><code>arn:aws:cloudtrail:us-east-2:123456789012:trail/MyTrail</code></p>
    /// <p>You cannot use this parameter with the <code>EventDataStore</code> parameter.</p>
    pub fn get_trail_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.trail_name
    }
    /// <p>Specifies the ARN (or ID suffix of the ARN) of the event data store for which you want to get Insights selectors.</p>
    /// <p>You cannot use this parameter with the <code>TrailName</code> parameter.</p>
    pub fn event_data_store(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_data_store = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ARN (or ID suffix of the ARN) of the event data store for which you want to get Insights selectors.</p>
    /// <p>You cannot use this parameter with the <code>TrailName</code> parameter.</p>
    pub fn set_event_data_store(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_data_store = input;
        self
    }
    /// <p>Specifies the ARN (or ID suffix of the ARN) of the event data store for which you want to get Insights selectors.</p>
    /// <p>You cannot use this parameter with the <code>TrailName</code> parameter.</p>
    pub fn get_event_data_store(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_data_store
    }
    /// Consumes the builder and constructs a [`GetInsightSelectorsInput`](crate::operation::get_insight_selectors::GetInsightSelectorsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_insight_selectors::GetInsightSelectorsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_insight_selectors::GetInsightSelectorsInput {
            trail_name: self.trail_name,
            event_data_store: self.event_data_store,
        })
    }
}
