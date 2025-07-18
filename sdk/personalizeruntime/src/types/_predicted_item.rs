// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that identifies an item.</p>
/// <p>The and APIs return a list of <code>PredictedItem</code>s.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct PredictedItem {
    /// <p>The recommended item ID.</p>
    pub item_id: ::std::option::Option<::std::string::String>,
    /// <p>A numeric representation of the model's certainty that the item will be the next user selection. For more information on scoring logic, see <code>how-scores-work</code>.</p>
    pub score: ::std::option::Option<f64>,
    /// <p>The name of the promotion that included the predicted item.</p>
    pub promotion_name: ::std::option::Option<::std::string::String>,
    /// <p>Metadata about the item from your Items dataset.</p>
    pub metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>If you use User-Personalization-v2, a list of reasons for why the item was included in recommendations. Possible reasons include the following:</p>
    /// <ul>
    /// <li>
    /// <p>Promoted item - Indicates the item was included as part of a promotion that you applied in your recommendation request.</p></li>
    /// <li>
    /// <p>Exploration - Indicates the item was included with exploration. With exploration, recommendations include items with less interactions data or relevance for the user. For more information about exploration, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/use-case-recipe-features.html#about-exploration">Exploration</a>.</p></li>
    /// <li>
    /// <p>Popular item - Indicates the item was included as a placeholder popular item. If you use a filter, depending on how many recommendations the filter removes, Amazon Personalize might add placeholder items to meet the <code>numResults</code> for your recommendation request. These items are popular items, based on interactions data, that satisfy your filter criteria. They don't have a relevance score for the user.</p></li>
    /// </ul>
    pub reason: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl PredictedItem {
    /// <p>The recommended item ID.</p>
    pub fn item_id(&self) -> ::std::option::Option<&str> {
        self.item_id.as_deref()
    }
    /// <p>A numeric representation of the model's certainty that the item will be the next user selection. For more information on scoring logic, see <code>how-scores-work</code>.</p>
    pub fn score(&self) -> ::std::option::Option<f64> {
        self.score
    }
    /// <p>The name of the promotion that included the predicted item.</p>
    pub fn promotion_name(&self) -> ::std::option::Option<&str> {
        self.promotion_name.as_deref()
    }
    /// <p>Metadata about the item from your Items dataset.</p>
    pub fn metadata(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.metadata.as_ref()
    }
    /// <p>If you use User-Personalization-v2, a list of reasons for why the item was included in recommendations. Possible reasons include the following:</p>
    /// <ul>
    /// <li>
    /// <p>Promoted item - Indicates the item was included as part of a promotion that you applied in your recommendation request.</p></li>
    /// <li>
    /// <p>Exploration - Indicates the item was included with exploration. With exploration, recommendations include items with less interactions data or relevance for the user. For more information about exploration, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/use-case-recipe-features.html#about-exploration">Exploration</a>.</p></li>
    /// <li>
    /// <p>Popular item - Indicates the item was included as a placeholder popular item. If you use a filter, depending on how many recommendations the filter removes, Amazon Personalize might add placeholder items to meet the <code>numResults</code> for your recommendation request. These items are popular items, based on interactions data, that satisfy your filter criteria. They don't have a relevance score for the user.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reason.is_none()`.
    pub fn reason(&self) -> &[::std::string::String] {
        self.reason.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for PredictedItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("PredictedItem");
        formatter.field("item_id", &self.item_id);
        formatter.field("score", &self.score);
        formatter.field("promotion_name", &self.promotion_name);
        formatter.field("metadata", &"*** Sensitive Data Redacted ***");
        formatter.field("reason", &self.reason);
        formatter.finish()
    }
}
impl PredictedItem {
    /// Creates a new builder-style object to manufacture [`PredictedItem`](crate::types::PredictedItem).
    pub fn builder() -> crate::types::builders::PredictedItemBuilder {
        crate::types::builders::PredictedItemBuilder::default()
    }
}

/// A builder for [`PredictedItem`](crate::types::PredictedItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct PredictedItemBuilder {
    pub(crate) item_id: ::std::option::Option<::std::string::String>,
    pub(crate) score: ::std::option::Option<f64>,
    pub(crate) promotion_name: ::std::option::Option<::std::string::String>,
    pub(crate) metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) reason: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl PredictedItemBuilder {
    /// <p>The recommended item ID.</p>
    pub fn item_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.item_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The recommended item ID.</p>
    pub fn set_item_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.item_id = input;
        self
    }
    /// <p>The recommended item ID.</p>
    pub fn get_item_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.item_id
    }
    /// <p>A numeric representation of the model's certainty that the item will be the next user selection. For more information on scoring logic, see <code>how-scores-work</code>.</p>
    pub fn score(mut self, input: f64) -> Self {
        self.score = ::std::option::Option::Some(input);
        self
    }
    /// <p>A numeric representation of the model's certainty that the item will be the next user selection. For more information on scoring logic, see <code>how-scores-work</code>.</p>
    pub fn set_score(mut self, input: ::std::option::Option<f64>) -> Self {
        self.score = input;
        self
    }
    /// <p>A numeric representation of the model's certainty that the item will be the next user selection. For more information on scoring logic, see <code>how-scores-work</code>.</p>
    pub fn get_score(&self) -> &::std::option::Option<f64> {
        &self.score
    }
    /// <p>The name of the promotion that included the predicted item.</p>
    pub fn promotion_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.promotion_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the promotion that included the predicted item.</p>
    pub fn set_promotion_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.promotion_name = input;
        self
    }
    /// <p>The name of the promotion that included the predicted item.</p>
    pub fn get_promotion_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.promotion_name
    }
    /// Adds a key-value pair to `metadata`.
    ///
    /// To override the contents of this collection use [`set_metadata`](Self::set_metadata).
    ///
    /// <p>Metadata about the item from your Items dataset.</p>
    pub fn metadata(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.metadata.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.metadata = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Metadata about the item from your Items dataset.</p>
    pub fn set_metadata(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.metadata = input;
        self
    }
    /// <p>Metadata about the item from your Items dataset.</p>
    pub fn get_metadata(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.metadata
    }
    /// Appends an item to `reason`.
    ///
    /// To override the contents of this collection use [`set_reason`](Self::set_reason).
    ///
    /// <p>If you use User-Personalization-v2, a list of reasons for why the item was included in recommendations. Possible reasons include the following:</p>
    /// <ul>
    /// <li>
    /// <p>Promoted item - Indicates the item was included as part of a promotion that you applied in your recommendation request.</p></li>
    /// <li>
    /// <p>Exploration - Indicates the item was included with exploration. With exploration, recommendations include items with less interactions data or relevance for the user. For more information about exploration, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/use-case-recipe-features.html#about-exploration">Exploration</a>.</p></li>
    /// <li>
    /// <p>Popular item - Indicates the item was included as a placeholder popular item. If you use a filter, depending on how many recommendations the filter removes, Amazon Personalize might add placeholder items to meet the <code>numResults</code> for your recommendation request. These items are popular items, based on interactions data, that satisfy your filter criteria. They don't have a relevance score for the user.</p></li>
    /// </ul>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.reason.unwrap_or_default();
        v.push(input.into());
        self.reason = ::std::option::Option::Some(v);
        self
    }
    /// <p>If you use User-Personalization-v2, a list of reasons for why the item was included in recommendations. Possible reasons include the following:</p>
    /// <ul>
    /// <li>
    /// <p>Promoted item - Indicates the item was included as part of a promotion that you applied in your recommendation request.</p></li>
    /// <li>
    /// <p>Exploration - Indicates the item was included with exploration. With exploration, recommendations include items with less interactions data or relevance for the user. For more information about exploration, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/use-case-recipe-features.html#about-exploration">Exploration</a>.</p></li>
    /// <li>
    /// <p>Popular item - Indicates the item was included as a placeholder popular item. If you use a filter, depending on how many recommendations the filter removes, Amazon Personalize might add placeholder items to meet the <code>numResults</code> for your recommendation request. These items are popular items, based on interactions data, that satisfy your filter criteria. They don't have a relevance score for the user.</p></li>
    /// </ul>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.reason = input;
        self
    }
    /// <p>If you use User-Personalization-v2, a list of reasons for why the item was included in recommendations. Possible reasons include the following:</p>
    /// <ul>
    /// <li>
    /// <p>Promoted item - Indicates the item was included as part of a promotion that you applied in your recommendation request.</p></li>
    /// <li>
    /// <p>Exploration - Indicates the item was included with exploration. With exploration, recommendations include items with less interactions data or relevance for the user. For more information about exploration, see <a href="https://docs.aws.amazon.com/personalize/latest/dg/use-case-recipe-features.html#about-exploration">Exploration</a>.</p></li>
    /// <li>
    /// <p>Popular item - Indicates the item was included as a placeholder popular item. If you use a filter, depending on how many recommendations the filter removes, Amazon Personalize might add placeholder items to meet the <code>numResults</code> for your recommendation request. These items are popular items, based on interactions data, that satisfy your filter criteria. They don't have a relevance score for the user.</p></li>
    /// </ul>
    pub fn get_reason(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.reason
    }
    /// Consumes the builder and constructs a [`PredictedItem`](crate::types::PredictedItem).
    pub fn build(self) -> crate::types::PredictedItem {
        crate::types::PredictedItem {
            item_id: self.item_id,
            score: self.score,
            promotion_name: self.promotion_name,
            metadata: self.metadata,
            reason: self.reason,
        }
    }
}
impl ::std::fmt::Debug for PredictedItemBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("PredictedItemBuilder");
        formatter.field("item_id", &self.item_id);
        formatter.field("score", &self.score);
        formatter.field("promotion_name", &self.promotion_name);
        formatter.field("metadata", &"*** Sensitive Data Redacted ***");
        formatter.field("reason", &self.reason);
        formatter.finish()
    }
}
