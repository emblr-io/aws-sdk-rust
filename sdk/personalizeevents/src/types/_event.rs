// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents item interaction event information sent using the <code>PutEvents</code> API.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Event {
    /// <p>An ID associated with the event. If an event ID is not provided, Amazon Personalize generates a unique ID for the event. An event ID is not used as an input to the model. Amazon Personalize uses the event ID to distinguish unique events. Any subsequent events after the first with the same event ID are not used in model training.</p>
    pub event_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of event, such as click or download. This property corresponds to the <code>EVENT_TYPE</code> field of your Item interactions dataset's schema and depends on the types of events you are tracking.</p>
    pub event_type: ::std::string::String,
    /// <p>The event value that corresponds to the <code>EVENT_VALUE</code> field of the Item interactions schema.</p>
    pub event_value: ::std::option::Option<f32>,
    /// <p>The item ID key that corresponds to the <code>ITEM_ID</code> field of the Item interactions dataset's schema.</p>
    pub item_id: ::std::option::Option<::std::string::String>,
    /// <p>A string map of event-specific data that you might choose to record. For example, if a user rates a movie on your site, other than movie ID (<code>itemId</code>) and rating (<code>eventValue</code>) , you might also send the number of movie ratings made by the user.</p>
    /// <p>Each item in the map consists of a key-value pair. For example,</p>
    /// <p><code>{"numberOfRatings": "12"}</code></p>
    /// <p>The keys use camel case names that match the fields in the Item interactions dataset's schema. In the above example, the <code>numberOfRatings</code> would match the 'NUMBER_OF_RATINGS' field defined in the Item interactions dataset's schema.</p>
    /// <p>The following can't be included as a keyword for properties (case insensitive).</p>
    /// <ul>
    /// <li>
    /// <p>userId</p></li>
    /// <li>
    /// <p>sessionId</p></li>
    /// <li>
    /// <p>eventType</p></li>
    /// <li>
    /// <p>timestamp</p></li>
    /// <li>
    /// <p>recommendationId</p></li>
    /// <li>
    /// <p>impression</p></li>
    /// </ul>
    pub properties: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp (in Unix time) on the client side when the event occurred.</p>
    pub sent_at: ::aws_smithy_types::DateTime,
    /// <p>The ID of the list of recommendations that contains the item the user interacted with. Provide a <code>recommendationId</code> to have Amazon Personalize implicitly record the recommendations you show your user as impressions data. Or provide a <code>recommendationId</code> if you use a metric attribution to measure the impact of recommendations.</p>
    /// <p>For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>. For more information on creating a metric attribution see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub recommendation_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of item IDs that represents the sequence of items you have shown the user. For example, <code>\["itemId1", "itemId2", "itemId3"\]</code>. Provide a list of items to manually record impressions data for an event. For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>.</p>
    pub impression: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Contains information about the metric attribution associated with an event. For more information about metric attributions, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub metric_attribution: ::std::option::Option<crate::types::MetricAttribution>,
}
impl Event {
    /// <p>An ID associated with the event. If an event ID is not provided, Amazon Personalize generates a unique ID for the event. An event ID is not used as an input to the model. Amazon Personalize uses the event ID to distinguish unique events. Any subsequent events after the first with the same event ID are not used in model training.</p>
    pub fn event_id(&self) -> ::std::option::Option<&str> {
        self.event_id.as_deref()
    }
    /// <p>The type of event, such as click or download. This property corresponds to the <code>EVENT_TYPE</code> field of your Item interactions dataset's schema and depends on the types of events you are tracking.</p>
    pub fn event_type(&self) -> &str {
        use std::ops::Deref;
        self.event_type.deref()
    }
    /// <p>The event value that corresponds to the <code>EVENT_VALUE</code> field of the Item interactions schema.</p>
    pub fn event_value(&self) -> ::std::option::Option<f32> {
        self.event_value
    }
    /// <p>The item ID key that corresponds to the <code>ITEM_ID</code> field of the Item interactions dataset's schema.</p>
    pub fn item_id(&self) -> ::std::option::Option<&str> {
        self.item_id.as_deref()
    }
    /// <p>A string map of event-specific data that you might choose to record. For example, if a user rates a movie on your site, other than movie ID (<code>itemId</code>) and rating (<code>eventValue</code>) , you might also send the number of movie ratings made by the user.</p>
    /// <p>Each item in the map consists of a key-value pair. For example,</p>
    /// <p><code>{"numberOfRatings": "12"}</code></p>
    /// <p>The keys use camel case names that match the fields in the Item interactions dataset's schema. In the above example, the <code>numberOfRatings</code> would match the 'NUMBER_OF_RATINGS' field defined in the Item interactions dataset's schema.</p>
    /// <p>The following can't be included as a keyword for properties (case insensitive).</p>
    /// <ul>
    /// <li>
    /// <p>userId</p></li>
    /// <li>
    /// <p>sessionId</p></li>
    /// <li>
    /// <p>eventType</p></li>
    /// <li>
    /// <p>timestamp</p></li>
    /// <li>
    /// <p>recommendationId</p></li>
    /// <li>
    /// <p>impression</p></li>
    /// </ul>
    pub fn properties(&self) -> ::std::option::Option<&str> {
        self.properties.as_deref()
    }
    /// <p>The timestamp (in Unix time) on the client side when the event occurred.</p>
    pub fn sent_at(&self) -> &::aws_smithy_types::DateTime {
        &self.sent_at
    }
    /// <p>The ID of the list of recommendations that contains the item the user interacted with. Provide a <code>recommendationId</code> to have Amazon Personalize implicitly record the recommendations you show your user as impressions data. Or provide a <code>recommendationId</code> if you use a metric attribution to measure the impact of recommendations.</p>
    /// <p>For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>. For more information on creating a metric attribution see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn recommendation_id(&self) -> ::std::option::Option<&str> {
        self.recommendation_id.as_deref()
    }
    /// <p>A list of item IDs that represents the sequence of items you have shown the user. For example, <code>\["itemId1", "itemId2", "itemId3"\]</code>. Provide a list of items to manually record impressions data for an event. For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.impression.is_none()`.
    pub fn impression(&self) -> &[::std::string::String] {
        self.impression.as_deref().unwrap_or_default()
    }
    /// <p>Contains information about the metric attribution associated with an event. For more information about metric attributions, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn metric_attribution(&self) -> ::std::option::Option<&crate::types::MetricAttribution> {
        self.metric_attribution.as_ref()
    }
}
impl ::std::fmt::Debug for Event {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Event");
        formatter.field("event_id", &"*** Sensitive Data Redacted ***");
        formatter.field("event_type", &"*** Sensitive Data Redacted ***");
        formatter.field("event_value", &"*** Sensitive Data Redacted ***");
        formatter.field("item_id", &"*** Sensitive Data Redacted ***");
        formatter.field("properties", &"*** Sensitive Data Redacted ***");
        formatter.field("sent_at", &"*** Sensitive Data Redacted ***");
        formatter.field("recommendation_id", &"*** Sensitive Data Redacted ***");
        formatter.field("impression", &"*** Sensitive Data Redacted ***");
        formatter.field("metric_attribution", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl Event {
    /// Creates a new builder-style object to manufacture [`Event`](crate::types::Event).
    pub fn builder() -> crate::types::builders::EventBuilder {
        crate::types::builders::EventBuilder::default()
    }
}

/// A builder for [`Event`](crate::types::Event).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct EventBuilder {
    pub(crate) event_id: ::std::option::Option<::std::string::String>,
    pub(crate) event_type: ::std::option::Option<::std::string::String>,
    pub(crate) event_value: ::std::option::Option<f32>,
    pub(crate) item_id: ::std::option::Option<::std::string::String>,
    pub(crate) properties: ::std::option::Option<::std::string::String>,
    pub(crate) sent_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) recommendation_id: ::std::option::Option<::std::string::String>,
    pub(crate) impression: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) metric_attribution: ::std::option::Option<crate::types::MetricAttribution>,
}
impl EventBuilder {
    /// <p>An ID associated with the event. If an event ID is not provided, Amazon Personalize generates a unique ID for the event. An event ID is not used as an input to the model. Amazon Personalize uses the event ID to distinguish unique events. Any subsequent events after the first with the same event ID are not used in model training.</p>
    pub fn event_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An ID associated with the event. If an event ID is not provided, Amazon Personalize generates a unique ID for the event. An event ID is not used as an input to the model. Amazon Personalize uses the event ID to distinguish unique events. Any subsequent events after the first with the same event ID are not used in model training.</p>
    pub fn set_event_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_id = input;
        self
    }
    /// <p>An ID associated with the event. If an event ID is not provided, Amazon Personalize generates a unique ID for the event. An event ID is not used as an input to the model. Amazon Personalize uses the event ID to distinguish unique events. Any subsequent events after the first with the same event ID are not used in model training.</p>
    pub fn get_event_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_id
    }
    /// <p>The type of event, such as click or download. This property corresponds to the <code>EVENT_TYPE</code> field of your Item interactions dataset's schema and depends on the types of events you are tracking.</p>
    /// This field is required.
    pub fn event_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of event, such as click or download. This property corresponds to the <code>EVENT_TYPE</code> field of your Item interactions dataset's schema and depends on the types of events you are tracking.</p>
    pub fn set_event_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_type = input;
        self
    }
    /// <p>The type of event, such as click or download. This property corresponds to the <code>EVENT_TYPE</code> field of your Item interactions dataset's schema and depends on the types of events you are tracking.</p>
    pub fn get_event_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_type
    }
    /// <p>The event value that corresponds to the <code>EVENT_VALUE</code> field of the Item interactions schema.</p>
    pub fn event_value(mut self, input: f32) -> Self {
        self.event_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The event value that corresponds to the <code>EVENT_VALUE</code> field of the Item interactions schema.</p>
    pub fn set_event_value(mut self, input: ::std::option::Option<f32>) -> Self {
        self.event_value = input;
        self
    }
    /// <p>The event value that corresponds to the <code>EVENT_VALUE</code> field of the Item interactions schema.</p>
    pub fn get_event_value(&self) -> &::std::option::Option<f32> {
        &self.event_value
    }
    /// <p>The item ID key that corresponds to the <code>ITEM_ID</code> field of the Item interactions dataset's schema.</p>
    pub fn item_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.item_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The item ID key that corresponds to the <code>ITEM_ID</code> field of the Item interactions dataset's schema.</p>
    pub fn set_item_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.item_id = input;
        self
    }
    /// <p>The item ID key that corresponds to the <code>ITEM_ID</code> field of the Item interactions dataset's schema.</p>
    pub fn get_item_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.item_id
    }
    /// <p>A string map of event-specific data that you might choose to record. For example, if a user rates a movie on your site, other than movie ID (<code>itemId</code>) and rating (<code>eventValue</code>) , you might also send the number of movie ratings made by the user.</p>
    /// <p>Each item in the map consists of a key-value pair. For example,</p>
    /// <p><code>{"numberOfRatings": "12"}</code></p>
    /// <p>The keys use camel case names that match the fields in the Item interactions dataset's schema. In the above example, the <code>numberOfRatings</code> would match the 'NUMBER_OF_RATINGS' field defined in the Item interactions dataset's schema.</p>
    /// <p>The following can't be included as a keyword for properties (case insensitive).</p>
    /// <ul>
    /// <li>
    /// <p>userId</p></li>
    /// <li>
    /// <p>sessionId</p></li>
    /// <li>
    /// <p>eventType</p></li>
    /// <li>
    /// <p>timestamp</p></li>
    /// <li>
    /// <p>recommendationId</p></li>
    /// <li>
    /// <p>impression</p></li>
    /// </ul>
    pub fn properties(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.properties = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string map of event-specific data that you might choose to record. For example, if a user rates a movie on your site, other than movie ID (<code>itemId</code>) and rating (<code>eventValue</code>) , you might also send the number of movie ratings made by the user.</p>
    /// <p>Each item in the map consists of a key-value pair. For example,</p>
    /// <p><code>{"numberOfRatings": "12"}</code></p>
    /// <p>The keys use camel case names that match the fields in the Item interactions dataset's schema. In the above example, the <code>numberOfRatings</code> would match the 'NUMBER_OF_RATINGS' field defined in the Item interactions dataset's schema.</p>
    /// <p>The following can't be included as a keyword for properties (case insensitive).</p>
    /// <ul>
    /// <li>
    /// <p>userId</p></li>
    /// <li>
    /// <p>sessionId</p></li>
    /// <li>
    /// <p>eventType</p></li>
    /// <li>
    /// <p>timestamp</p></li>
    /// <li>
    /// <p>recommendationId</p></li>
    /// <li>
    /// <p>impression</p></li>
    /// </ul>
    pub fn set_properties(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.properties = input;
        self
    }
    /// <p>A string map of event-specific data that you might choose to record. For example, if a user rates a movie on your site, other than movie ID (<code>itemId</code>) and rating (<code>eventValue</code>) , you might also send the number of movie ratings made by the user.</p>
    /// <p>Each item in the map consists of a key-value pair. For example,</p>
    /// <p><code>{"numberOfRatings": "12"}</code></p>
    /// <p>The keys use camel case names that match the fields in the Item interactions dataset's schema. In the above example, the <code>numberOfRatings</code> would match the 'NUMBER_OF_RATINGS' field defined in the Item interactions dataset's schema.</p>
    /// <p>The following can't be included as a keyword for properties (case insensitive).</p>
    /// <ul>
    /// <li>
    /// <p>userId</p></li>
    /// <li>
    /// <p>sessionId</p></li>
    /// <li>
    /// <p>eventType</p></li>
    /// <li>
    /// <p>timestamp</p></li>
    /// <li>
    /// <p>recommendationId</p></li>
    /// <li>
    /// <p>impression</p></li>
    /// </ul>
    pub fn get_properties(&self) -> &::std::option::Option<::std::string::String> {
        &self.properties
    }
    /// <p>The timestamp (in Unix time) on the client side when the event occurred.</p>
    /// This field is required.
    pub fn sent_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.sent_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp (in Unix time) on the client side when the event occurred.</p>
    pub fn set_sent_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.sent_at = input;
        self
    }
    /// <p>The timestamp (in Unix time) on the client side when the event occurred.</p>
    pub fn get_sent_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.sent_at
    }
    /// <p>The ID of the list of recommendations that contains the item the user interacted with. Provide a <code>recommendationId</code> to have Amazon Personalize implicitly record the recommendations you show your user as impressions data. Or provide a <code>recommendationId</code> if you use a metric attribution to measure the impact of recommendations.</p>
    /// <p>For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>. For more information on creating a metric attribution see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn recommendation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the list of recommendations that contains the item the user interacted with. Provide a <code>recommendationId</code> to have Amazon Personalize implicitly record the recommendations you show your user as impressions data. Or provide a <code>recommendationId</code> if you use a metric attribution to measure the impact of recommendations.</p>
    /// <p>For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>. For more information on creating a metric attribution see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn set_recommendation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_id = input;
        self
    }
    /// <p>The ID of the list of recommendations that contains the item the user interacted with. Provide a <code>recommendationId</code> to have Amazon Personalize implicitly record the recommendations you show your user as impressions data. Or provide a <code>recommendationId</code> if you use a metric attribution to measure the impact of recommendations.</p>
    /// <p>For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>. For more information on creating a metric attribution see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn get_recommendation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_id
    }
    /// Appends an item to `impression`.
    ///
    /// To override the contents of this collection use [`set_impression`](Self::set_impression).
    ///
    /// <p>A list of item IDs that represents the sequence of items you have shown the user. For example, <code>\["itemId1", "itemId2", "itemId3"\]</code>. Provide a list of items to manually record impressions data for an event. For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>.</p>
    pub fn impression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.impression.unwrap_or_default();
        v.push(input.into());
        self.impression = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of item IDs that represents the sequence of items you have shown the user. For example, <code>\["itemId1", "itemId2", "itemId3"\]</code>. Provide a list of items to manually record impressions data for an event. For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>.</p>
    pub fn set_impression(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.impression = input;
        self
    }
    /// <p>A list of item IDs that represents the sequence of items you have shown the user. For example, <code>\["itemId1", "itemId2", "itemId3"\]</code>. Provide a list of items to manually record impressions data for an event. For more information on recording impressions data, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/recording-events.html#putevents-including-impressions-data">Recording impressions data</a>.</p>
    pub fn get_impression(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.impression
    }
    /// <p>Contains information about the metric attribution associated with an event. For more information about metric attributions, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn metric_attribution(mut self, input: crate::types::MetricAttribution) -> Self {
        self.metric_attribution = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the metric attribution associated with an event. For more information about metric attributions, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn set_metric_attribution(mut self, input: ::std::option::Option<crate::types::MetricAttribution>) -> Self {
        self.metric_attribution = input;
        self
    }
    /// <p>Contains information about the metric attribution associated with an event. For more information about metric attributions, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/measuring-recommendation-impact.html">Measuring impact of recommendations</a>.</p>
    pub fn get_metric_attribution(&self) -> &::std::option::Option<crate::types::MetricAttribution> {
        &self.metric_attribution
    }
    /// Consumes the builder and constructs a [`Event`](crate::types::Event).
    /// This method will fail if any of the following fields are not set:
    /// - [`event_type`](crate::types::builders::EventBuilder::event_type)
    /// - [`sent_at`](crate::types::builders::EventBuilder::sent_at)
    pub fn build(self) -> ::std::result::Result<crate::types::Event, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Event {
            event_id: self.event_id,
            event_type: self.event_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "event_type",
                    "event_type was not specified but it is required when building Event",
                )
            })?,
            event_value: self.event_value,
            item_id: self.item_id,
            properties: self.properties,
            sent_at: self.sent_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sent_at",
                    "sent_at was not specified but it is required when building Event",
                )
            })?,
            recommendation_id: self.recommendation_id,
            impression: self.impression,
            metric_attribution: self.metric_attribution,
        })
    }
}
impl ::std::fmt::Debug for EventBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EventBuilder");
        formatter.field("event_id", &"*** Sensitive Data Redacted ***");
        formatter.field("event_type", &"*** Sensitive Data Redacted ***");
        formatter.field("event_value", &"*** Sensitive Data Redacted ***");
        formatter.field("item_id", &"*** Sensitive Data Redacted ***");
        formatter.field("properties", &"*** Sensitive Data Redacted ***");
        formatter.field("sent_at", &"*** Sensitive Data Redacted ***");
        formatter.field("recommendation_id", &"*** Sensitive Data Redacted ***");
        formatter.field("impression", &"*** Sensitive Data Redacted ***");
        formatter.field("metric_attribution", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
