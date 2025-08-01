// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateGeofenceCollectionInput {
    /// <p>A custom name for the geofence collection.</p>
    /// <p>Requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only alphanumeric characters (A–Z, a–z, 0–9), hyphens (-), periods (.), and underscores (_).</p></li>
    /// <li>
    /// <p>Must be a unique geofence collection name.</p></li>
    /// <li>
    /// <p>No spaces allowed. For example, <code>ExampleGeofenceCollection</code>.</p></li>
    /// </ul>
    pub collection_name: ::std::option::Option<::std::string::String>,
    /// <p>No longer used. If included, the only allowed value is <code>RequestBasedUsage</code>.</p>
    #[deprecated(note = "Deprecated. If included, the only allowed value is RequestBasedUsage.", since = "2022-02-01")]
    pub pricing_plan: ::std::option::Option<crate::types::PricingPlan>,
    /// <p>This parameter is no longer used.</p>
    #[deprecated(note = "Deprecated. No longer allowed.", since = "2022-02-01")]
    pub pricing_plan_data_source: ::std::option::Option<::std::string::String>,
    /// <p>An optional description for the geofence collection.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Applies one or more tags to the geofence collection. A tag is a key-value pair helps manage, identify, search, and filter your resources by labelling them.</p>
    /// <p>Format: <code>"key" : "value"</code></p>
    /// <p>Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum 50 tags per resource</p></li>
    /// <li>
    /// <p>Each resource tag must be unique with a maximum of one value.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Can use alphanumeric characters (A–Z, a–z, 0–9), and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Cannot use "aws:" as a prefix for a key.</p></li>
    /// </ul>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A key identifier for an <a href="https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html">Amazon Web Services KMS customer managed key</a>. Enter a key ID, key ARN, alias name, or alias ARN.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
}
impl CreateGeofenceCollectionInput {
    /// <p>A custom name for the geofence collection.</p>
    /// <p>Requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only alphanumeric characters (A–Z, a–z, 0–9), hyphens (-), periods (.), and underscores (_).</p></li>
    /// <li>
    /// <p>Must be a unique geofence collection name.</p></li>
    /// <li>
    /// <p>No spaces allowed. For example, <code>ExampleGeofenceCollection</code>.</p></li>
    /// </ul>
    pub fn collection_name(&self) -> ::std::option::Option<&str> {
        self.collection_name.as_deref()
    }
    /// <p>No longer used. If included, the only allowed value is <code>RequestBasedUsage</code>.</p>
    #[deprecated(note = "Deprecated. If included, the only allowed value is RequestBasedUsage.", since = "2022-02-01")]
    pub fn pricing_plan(&self) -> ::std::option::Option<&crate::types::PricingPlan> {
        self.pricing_plan.as_ref()
    }
    /// <p>This parameter is no longer used.</p>
    #[deprecated(note = "Deprecated. No longer allowed.", since = "2022-02-01")]
    pub fn pricing_plan_data_source(&self) -> ::std::option::Option<&str> {
        self.pricing_plan_data_source.as_deref()
    }
    /// <p>An optional description for the geofence collection.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Applies one or more tags to the geofence collection. A tag is a key-value pair helps manage, identify, search, and filter your resources by labelling them.</p>
    /// <p>Format: <code>"key" : "value"</code></p>
    /// <p>Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum 50 tags per resource</p></li>
    /// <li>
    /// <p>Each resource tag must be unique with a maximum of one value.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Can use alphanumeric characters (A–Z, a–z, 0–9), and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Cannot use "aws:" as a prefix for a key.</p></li>
    /// </ul>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>A key identifier for an <a href="https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html">Amazon Web Services KMS customer managed key</a>. Enter a key ID, key ARN, alias name, or alias ARN.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
}
impl CreateGeofenceCollectionInput {
    /// Creates a new builder-style object to manufacture [`CreateGeofenceCollectionInput`](crate::operation::create_geofence_collection::CreateGeofenceCollectionInput).
    pub fn builder() -> crate::operation::create_geofence_collection::builders::CreateGeofenceCollectionInputBuilder {
        crate::operation::create_geofence_collection::builders::CreateGeofenceCollectionInputBuilder::default()
    }
}

/// A builder for [`CreateGeofenceCollectionInput`](crate::operation::create_geofence_collection::CreateGeofenceCollectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateGeofenceCollectionInputBuilder {
    pub(crate) collection_name: ::std::option::Option<::std::string::String>,
    pub(crate) pricing_plan: ::std::option::Option<crate::types::PricingPlan>,
    pub(crate) pricing_plan_data_source: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
}
impl CreateGeofenceCollectionInputBuilder {
    /// <p>A custom name for the geofence collection.</p>
    /// <p>Requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only alphanumeric characters (A–Z, a–z, 0–9), hyphens (-), periods (.), and underscores (_).</p></li>
    /// <li>
    /// <p>Must be a unique geofence collection name.</p></li>
    /// <li>
    /// <p>No spaces allowed. For example, <code>ExampleGeofenceCollection</code>.</p></li>
    /// </ul>
    /// This field is required.
    pub fn collection_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collection_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A custom name for the geofence collection.</p>
    /// <p>Requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only alphanumeric characters (A–Z, a–z, 0–9), hyphens (-), periods (.), and underscores (_).</p></li>
    /// <li>
    /// <p>Must be a unique geofence collection name.</p></li>
    /// <li>
    /// <p>No spaces allowed. For example, <code>ExampleGeofenceCollection</code>.</p></li>
    /// </ul>
    pub fn set_collection_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collection_name = input;
        self
    }
    /// <p>A custom name for the geofence collection.</p>
    /// <p>Requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only alphanumeric characters (A–Z, a–z, 0–9), hyphens (-), periods (.), and underscores (_).</p></li>
    /// <li>
    /// <p>Must be a unique geofence collection name.</p></li>
    /// <li>
    /// <p>No spaces allowed. For example, <code>ExampleGeofenceCollection</code>.</p></li>
    /// </ul>
    pub fn get_collection_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.collection_name
    }
    /// <p>No longer used. If included, the only allowed value is <code>RequestBasedUsage</code>.</p>
    #[deprecated(note = "Deprecated. If included, the only allowed value is RequestBasedUsage.", since = "2022-02-01")]
    pub fn pricing_plan(mut self, input: crate::types::PricingPlan) -> Self {
        self.pricing_plan = ::std::option::Option::Some(input);
        self
    }
    /// <p>No longer used. If included, the only allowed value is <code>RequestBasedUsage</code>.</p>
    #[deprecated(note = "Deprecated. If included, the only allowed value is RequestBasedUsage.", since = "2022-02-01")]
    pub fn set_pricing_plan(mut self, input: ::std::option::Option<crate::types::PricingPlan>) -> Self {
        self.pricing_plan = input;
        self
    }
    /// <p>No longer used. If included, the only allowed value is <code>RequestBasedUsage</code>.</p>
    #[deprecated(note = "Deprecated. If included, the only allowed value is RequestBasedUsage.", since = "2022-02-01")]
    pub fn get_pricing_plan(&self) -> &::std::option::Option<crate::types::PricingPlan> {
        &self.pricing_plan
    }
    /// <p>This parameter is no longer used.</p>
    #[deprecated(note = "Deprecated. No longer allowed.", since = "2022-02-01")]
    pub fn pricing_plan_data_source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pricing_plan_data_source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This parameter is no longer used.</p>
    #[deprecated(note = "Deprecated. No longer allowed.", since = "2022-02-01")]
    pub fn set_pricing_plan_data_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pricing_plan_data_source = input;
        self
    }
    /// <p>This parameter is no longer used.</p>
    #[deprecated(note = "Deprecated. No longer allowed.", since = "2022-02-01")]
    pub fn get_pricing_plan_data_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.pricing_plan_data_source
    }
    /// <p>An optional description for the geofence collection.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional description for the geofence collection.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>An optional description for the geofence collection.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Applies one or more tags to the geofence collection. A tag is a key-value pair helps manage, identify, search, and filter your resources by labelling them.</p>
    /// <p>Format: <code>"key" : "value"</code></p>
    /// <p>Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum 50 tags per resource</p></li>
    /// <li>
    /// <p>Each resource tag must be unique with a maximum of one value.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Can use alphanumeric characters (A–Z, a–z, 0–9), and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Cannot use "aws:" as a prefix for a key.</p></li>
    /// </ul>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Applies one or more tags to the geofence collection. A tag is a key-value pair helps manage, identify, search, and filter your resources by labelling them.</p>
    /// <p>Format: <code>"key" : "value"</code></p>
    /// <p>Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum 50 tags per resource</p></li>
    /// <li>
    /// <p>Each resource tag must be unique with a maximum of one value.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Can use alphanumeric characters (A–Z, a–z, 0–9), and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Cannot use "aws:" as a prefix for a key.</p></li>
    /// </ul>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Applies one or more tags to the geofence collection. A tag is a key-value pair helps manage, identify, search, and filter your resources by labelling them.</p>
    /// <p>Format: <code>"key" : "value"</code></p>
    /// <p>Restrictions:</p>
    /// <ul>
    /// <li>
    /// <p>Maximum 50 tags per resource</p></li>
    /// <li>
    /// <p>Each resource tag must be unique with a maximum of one value.</p></li>
    /// <li>
    /// <p>Maximum key length: 128 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Maximum value length: 256 Unicode characters in UTF-8</p></li>
    /// <li>
    /// <p>Can use alphanumeric characters (A–Z, a–z, 0–9), and the following characters: + - = . _ : / @.</p></li>
    /// <li>
    /// <p>Cannot use "aws:" as a prefix for a key.</p></li>
    /// </ul>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>A key identifier for an <a href="https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html">Amazon Web Services KMS customer managed key</a>. Enter a key ID, key ARN, alias name, or alias ARN.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A key identifier for an <a href="https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html">Amazon Web Services KMS customer managed key</a>. Enter a key ID, key ARN, alias name, or alias ARN.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>A key identifier for an <a href="https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html">Amazon Web Services KMS customer managed key</a>. Enter a key ID, key ARN, alias name, or alias ARN.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Consumes the builder and constructs a [`CreateGeofenceCollectionInput`](crate::operation::create_geofence_collection::CreateGeofenceCollectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_geofence_collection::CreateGeofenceCollectionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_geofence_collection::CreateGeofenceCollectionInput {
            collection_name: self.collection_name,
            pricing_plan: self.pricing_plan,
            pricing_plan_data_source: self.pricing_plan_data_source,
            description: self.description,
            tags: self.tags,
            kms_key_id: self.kms_key_id,
        })
    }
}
