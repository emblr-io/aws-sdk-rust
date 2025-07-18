// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateFeatureInput {
    /// <p>The name or ARN of the project that contains the feature to be updated.</p>
    pub project: ::std::option::Option<::std::string::String>,
    /// <p>The name of the feature to be updated.</p>
    pub feature: ::std::option::Option<::std::string::String>,
    /// <p>Specify <code>ALL_RULES</code> to activate the traffic allocation specified by any ongoing launches or experiments. Specify <code>DEFAULT_VARIATION</code> to serve the default variation to all users instead.</p>
    pub evaluation_strategy: ::std::option::Option<crate::types::FeatureEvaluationStrategy>,
    /// <p>An optional description of the feature.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>To update variation configurations for this feature, or add new ones, specify this structure. In this array, include any variations that you want to add or update. If the array includes a variation name that already exists for this feature, it is updated. If it includes a new variation name, it is added as a new variation.</p>
    pub add_or_update_variations: ::std::option::Option<::std::vec::Vec<crate::types::VariationConfig>>,
    /// <p>Removes a variation from the feature. If the variation you specify doesn't exist, then this makes no change and does not report an error.</p>
    /// <p>This operation fails if you try to remove a variation that is part of an ongoing launch or experiment.</p>
    pub remove_variations: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the variation to use as the default variation. The default variation is served to users who are not allocated to any ongoing launches or experiments of this feature.</p>
    pub default_variation: ::std::option::Option<::std::string::String>,
    /// <p>Specified users that should always be served a specific variation of a feature. Each user is specified by a key-value pair . For each key, specify a user by entering their user ID, account ID, or some other identifier. For the value, specify the name of the variation that they are to be served.</p>
    /// <p>This parameter is limited to 2500 overrides or a total of 40KB. The 40KB limit includes an overhead of 6 bytes per override.</p>
    pub entity_overrides: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateFeatureInput {
    /// <p>The name or ARN of the project that contains the feature to be updated.</p>
    pub fn project(&self) -> ::std::option::Option<&str> {
        self.project.as_deref()
    }
    /// <p>The name of the feature to be updated.</p>
    pub fn feature(&self) -> ::std::option::Option<&str> {
        self.feature.as_deref()
    }
    /// <p>Specify <code>ALL_RULES</code> to activate the traffic allocation specified by any ongoing launches or experiments. Specify <code>DEFAULT_VARIATION</code> to serve the default variation to all users instead.</p>
    pub fn evaluation_strategy(&self) -> ::std::option::Option<&crate::types::FeatureEvaluationStrategy> {
        self.evaluation_strategy.as_ref()
    }
    /// <p>An optional description of the feature.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>To update variation configurations for this feature, or add new ones, specify this structure. In this array, include any variations that you want to add or update. If the array includes a variation name that already exists for this feature, it is updated. If it includes a new variation name, it is added as a new variation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.add_or_update_variations.is_none()`.
    pub fn add_or_update_variations(&self) -> &[crate::types::VariationConfig] {
        self.add_or_update_variations.as_deref().unwrap_or_default()
    }
    /// <p>Removes a variation from the feature. If the variation you specify doesn't exist, then this makes no change and does not report an error.</p>
    /// <p>This operation fails if you try to remove a variation that is part of an ongoing launch or experiment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.remove_variations.is_none()`.
    pub fn remove_variations(&self) -> &[::std::string::String] {
        self.remove_variations.as_deref().unwrap_or_default()
    }
    /// <p>The name of the variation to use as the default variation. The default variation is served to users who are not allocated to any ongoing launches or experiments of this feature.</p>
    pub fn default_variation(&self) -> ::std::option::Option<&str> {
        self.default_variation.as_deref()
    }
    /// <p>Specified users that should always be served a specific variation of a feature. Each user is specified by a key-value pair . For each key, specify a user by entering their user ID, account ID, or some other identifier. For the value, specify the name of the variation that they are to be served.</p>
    /// <p>This parameter is limited to 2500 overrides or a total of 40KB. The 40KB limit includes an overhead of 6 bytes per override.</p>
    pub fn entity_overrides(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.entity_overrides.as_ref()
    }
}
impl UpdateFeatureInput {
    /// Creates a new builder-style object to manufacture [`UpdateFeatureInput`](crate::operation::update_feature::UpdateFeatureInput).
    pub fn builder() -> crate::operation::update_feature::builders::UpdateFeatureInputBuilder {
        crate::operation::update_feature::builders::UpdateFeatureInputBuilder::default()
    }
}

/// A builder for [`UpdateFeatureInput`](crate::operation::update_feature::UpdateFeatureInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateFeatureInputBuilder {
    pub(crate) project: ::std::option::Option<::std::string::String>,
    pub(crate) feature: ::std::option::Option<::std::string::String>,
    pub(crate) evaluation_strategy: ::std::option::Option<crate::types::FeatureEvaluationStrategy>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) add_or_update_variations: ::std::option::Option<::std::vec::Vec<crate::types::VariationConfig>>,
    pub(crate) remove_variations: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) default_variation: ::std::option::Option<::std::string::String>,
    pub(crate) entity_overrides: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateFeatureInputBuilder {
    /// <p>The name or ARN of the project that contains the feature to be updated.</p>
    /// This field is required.
    pub fn project(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or ARN of the project that contains the feature to be updated.</p>
    pub fn set_project(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project = input;
        self
    }
    /// <p>The name or ARN of the project that contains the feature to be updated.</p>
    pub fn get_project(&self) -> &::std::option::Option<::std::string::String> {
        &self.project
    }
    /// <p>The name of the feature to be updated.</p>
    /// This field is required.
    pub fn feature(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.feature = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the feature to be updated.</p>
    pub fn set_feature(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.feature = input;
        self
    }
    /// <p>The name of the feature to be updated.</p>
    pub fn get_feature(&self) -> &::std::option::Option<::std::string::String> {
        &self.feature
    }
    /// <p>Specify <code>ALL_RULES</code> to activate the traffic allocation specified by any ongoing launches or experiments. Specify <code>DEFAULT_VARIATION</code> to serve the default variation to all users instead.</p>
    pub fn evaluation_strategy(mut self, input: crate::types::FeatureEvaluationStrategy) -> Self {
        self.evaluation_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify <code>ALL_RULES</code> to activate the traffic allocation specified by any ongoing launches or experiments. Specify <code>DEFAULT_VARIATION</code> to serve the default variation to all users instead.</p>
    pub fn set_evaluation_strategy(mut self, input: ::std::option::Option<crate::types::FeatureEvaluationStrategy>) -> Self {
        self.evaluation_strategy = input;
        self
    }
    /// <p>Specify <code>ALL_RULES</code> to activate the traffic allocation specified by any ongoing launches or experiments. Specify <code>DEFAULT_VARIATION</code> to serve the default variation to all users instead.</p>
    pub fn get_evaluation_strategy(&self) -> &::std::option::Option<crate::types::FeatureEvaluationStrategy> {
        &self.evaluation_strategy
    }
    /// <p>An optional description of the feature.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional description of the feature.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>An optional description of the feature.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `add_or_update_variations`.
    ///
    /// To override the contents of this collection use [`set_add_or_update_variations`](Self::set_add_or_update_variations).
    ///
    /// <p>To update variation configurations for this feature, or add new ones, specify this structure. In this array, include any variations that you want to add or update. If the array includes a variation name that already exists for this feature, it is updated. If it includes a new variation name, it is added as a new variation.</p>
    pub fn add_or_update_variations(mut self, input: crate::types::VariationConfig) -> Self {
        let mut v = self.add_or_update_variations.unwrap_or_default();
        v.push(input);
        self.add_or_update_variations = ::std::option::Option::Some(v);
        self
    }
    /// <p>To update variation configurations for this feature, or add new ones, specify this structure. In this array, include any variations that you want to add or update. If the array includes a variation name that already exists for this feature, it is updated. If it includes a new variation name, it is added as a new variation.</p>
    pub fn set_add_or_update_variations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VariationConfig>>) -> Self {
        self.add_or_update_variations = input;
        self
    }
    /// <p>To update variation configurations for this feature, or add new ones, specify this structure. In this array, include any variations that you want to add or update. If the array includes a variation name that already exists for this feature, it is updated. If it includes a new variation name, it is added as a new variation.</p>
    pub fn get_add_or_update_variations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VariationConfig>> {
        &self.add_or_update_variations
    }
    /// Appends an item to `remove_variations`.
    ///
    /// To override the contents of this collection use [`set_remove_variations`](Self::set_remove_variations).
    ///
    /// <p>Removes a variation from the feature. If the variation you specify doesn't exist, then this makes no change and does not report an error.</p>
    /// <p>This operation fails if you try to remove a variation that is part of an ongoing launch or experiment.</p>
    pub fn remove_variations(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.remove_variations.unwrap_or_default();
        v.push(input.into());
        self.remove_variations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Removes a variation from the feature. If the variation you specify doesn't exist, then this makes no change and does not report an error.</p>
    /// <p>This operation fails if you try to remove a variation that is part of an ongoing launch or experiment.</p>
    pub fn set_remove_variations(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.remove_variations = input;
        self
    }
    /// <p>Removes a variation from the feature. If the variation you specify doesn't exist, then this makes no change and does not report an error.</p>
    /// <p>This operation fails if you try to remove a variation that is part of an ongoing launch or experiment.</p>
    pub fn get_remove_variations(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.remove_variations
    }
    /// <p>The name of the variation to use as the default variation. The default variation is served to users who are not allocated to any ongoing launches or experiments of this feature.</p>
    pub fn default_variation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_variation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the variation to use as the default variation. The default variation is served to users who are not allocated to any ongoing launches or experiments of this feature.</p>
    pub fn set_default_variation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_variation = input;
        self
    }
    /// <p>The name of the variation to use as the default variation. The default variation is served to users who are not allocated to any ongoing launches or experiments of this feature.</p>
    pub fn get_default_variation(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_variation
    }
    /// Adds a key-value pair to `entity_overrides`.
    ///
    /// To override the contents of this collection use [`set_entity_overrides`](Self::set_entity_overrides).
    ///
    /// <p>Specified users that should always be served a specific variation of a feature. Each user is specified by a key-value pair . For each key, specify a user by entering their user ID, account ID, or some other identifier. For the value, specify the name of the variation that they are to be served.</p>
    /// <p>This parameter is limited to 2500 overrides or a total of 40KB. The 40KB limit includes an overhead of 6 bytes per override.</p>
    pub fn entity_overrides(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.entity_overrides.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.entity_overrides = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Specified users that should always be served a specific variation of a feature. Each user is specified by a key-value pair . For each key, specify a user by entering their user ID, account ID, or some other identifier. For the value, specify the name of the variation that they are to be served.</p>
    /// <p>This parameter is limited to 2500 overrides or a total of 40KB. The 40KB limit includes an overhead of 6 bytes per override.</p>
    pub fn set_entity_overrides(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.entity_overrides = input;
        self
    }
    /// <p>Specified users that should always be served a specific variation of a feature. Each user is specified by a key-value pair . For each key, specify a user by entering their user ID, account ID, or some other identifier. For the value, specify the name of the variation that they are to be served.</p>
    /// <p>This parameter is limited to 2500 overrides or a total of 40KB. The 40KB limit includes an overhead of 6 bytes per override.</p>
    pub fn get_entity_overrides(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.entity_overrides
    }
    /// Consumes the builder and constructs a [`UpdateFeatureInput`](crate::operation::update_feature::UpdateFeatureInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_feature::UpdateFeatureInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_feature::UpdateFeatureInput {
            project: self.project,
            feature: self.feature,
            evaluation_strategy: self.evaluation_strategy,
            description: self.description,
            add_or_update_variations: self.add_or_update_variations,
            remove_variations: self.remove_variations,
            default_variation: self.default_variation,
            entity_overrides: self.entity_overrides,
        })
    }
}
