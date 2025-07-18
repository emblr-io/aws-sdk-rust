// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AutocompleteInput {
    /// <p>The free-form text query to match addresses against. This is usually a partially typed address from an end user in an address box or form.</p><note>
    /// <p>The fields <code>QueryText</code>, and <code>QueryID</code> are mutually exclusive.</p>
    /// </note>
    pub query_text: ::std::option::Option<::std::string::String>,
    /// <p>An optional limit for the number of results returned in a single call.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The position in longitude and latitude that the results should be close to. Typically, place results returned are ranked higher the closer they are to this position. Stored in <code>\[lng, lat\]</code> and in the WSG84 format.</p><note>
    /// <p>The fields <code>BiasPosition</code>, <code>FilterBoundingBox</code>, and <code>FilterCircle</code> are mutually exclusive.</p>
    /// </note>
    pub bias_position: ::std::option::Option<::std::vec::Vec<f64>>,
    /// <p>A structure which contains a set of inclusion/exclusion properties that results must possess in order to be returned as a result.</p>
    pub filter: ::std::option::Option<crate::types::AutocompleteFilter>,
    /// <p>The <code>PostalCodeMode</code> affects how postal code results are returned. If a postal code spans multiple localities and this value is empty, partial district or locality information may be returned under a single postal code result entry. If it's populated with the value <code>EnumerateSpannedLocalities</code>, all cities in that postal code are returned.</p>
    pub postal_code_mode: ::std::option::Option<crate::types::PostalCodeMode>,
    /// <p>A list of optional additional parameters that can be requested for each result.</p>
    pub additional_features: ::std::option::Option<::std::vec::Vec<crate::types::AutocompleteAdditionalFeature>>,
    /// <p>A list of <a href="https://en.wikipedia.org/wiki/IETF_language_tag">BCP 47</a> compliant language codes for the results to be rendered in. If there is no data for the result in the requested language, data will be returned in the default language for the entry.</p>
    pub language: ::std::option::Option<::std::string::String>,
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    /// <p>The following political views are currently supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ARG</code>: Argentina's view on the Southern Patagonian Ice Field and Tierra Del Fuego, including the Falkland Islands, South Georgia, and South Sandwich Islands</p></li>
    /// <li>
    /// <p><code>EGY</code>: Egypt's view on Bir Tawil</p></li>
    /// <li>
    /// <p><code>IND</code>: India's view on Gilgit-Baltistan</p></li>
    /// <li>
    /// <p><code>KEN</code>: Kenya's view on the Ilemi Triangle</p></li>
    /// <li>
    /// <p><code>MAR</code>: Morocco's view on Western Sahara</p></li>
    /// <li>
    /// <p><code>RUS</code>: Russia's view on Crimea</p></li>
    /// <li>
    /// <p><code>SDN</code>: Sudan's view on the Halaib Triangle</p></li>
    /// <li>
    /// <p><code>SRB</code>: Serbia's view on Kosovo, Vukovar, and Sarengrad Islands</p></li>
    /// <li>
    /// <p><code>SUR</code>: Suriname's view on the Courantyne Headwaters and Lawa Headwaters</p></li>
    /// <li>
    /// <p><code>SYR</code>: Syria's view on the Golan Heights</p></li>
    /// <li>
    /// <p><code>TUR</code>: Turkey's view on Cyprus and Northern Cyprus</p></li>
    /// <li>
    /// <p><code>TZA</code>: Tanzania's view on Lake Malawi</p></li>
    /// <li>
    /// <p><code>URY</code>: Uruguay's view on Rincon de Artigas</p></li>
    /// <li>
    /// <p><code>VNM</code>: Vietnam's view on the Paracel Islands and Spratly Islands</p></li>
    /// </ul>
    pub political_view: ::std::option::Option<::std::string::String>,
    /// <p>Indicates if the results will be stored. Defaults to <code>SingleUse</code>, if left empty.</p>
    pub intended_use: ::std::option::Option<crate::types::AutocompleteIntendedUse>,
    /// <p>Optional: The API key to be used for authorization. Either an API key or valid SigV4 signature must be provided when making a request.</p>
    pub key: ::std::option::Option<::std::string::String>,
}
impl AutocompleteInput {
    /// <p>The free-form text query to match addresses against. This is usually a partially typed address from an end user in an address box or form.</p><note>
    /// <p>The fields <code>QueryText</code>, and <code>QueryID</code> are mutually exclusive.</p>
    /// </note>
    pub fn query_text(&self) -> ::std::option::Option<&str> {
        self.query_text.as_deref()
    }
    /// <p>An optional limit for the number of results returned in a single call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The position in longitude and latitude that the results should be close to. Typically, place results returned are ranked higher the closer they are to this position. Stored in <code>\[lng, lat\]</code> and in the WSG84 format.</p><note>
    /// <p>The fields <code>BiasPosition</code>, <code>FilterBoundingBox</code>, and <code>FilterCircle</code> are mutually exclusive.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.bias_position.is_none()`.
    pub fn bias_position(&self) -> &[f64] {
        self.bias_position.as_deref().unwrap_or_default()
    }
    /// <p>A structure which contains a set of inclusion/exclusion properties that results must possess in order to be returned as a result.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::AutocompleteFilter> {
        self.filter.as_ref()
    }
    /// <p>The <code>PostalCodeMode</code> affects how postal code results are returned. If a postal code spans multiple localities and this value is empty, partial district or locality information may be returned under a single postal code result entry. If it's populated with the value <code>EnumerateSpannedLocalities</code>, all cities in that postal code are returned.</p>
    pub fn postal_code_mode(&self) -> ::std::option::Option<&crate::types::PostalCodeMode> {
        self.postal_code_mode.as_ref()
    }
    /// <p>A list of optional additional parameters that can be requested for each result.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.additional_features.is_none()`.
    pub fn additional_features(&self) -> &[crate::types::AutocompleteAdditionalFeature] {
        self.additional_features.as_deref().unwrap_or_default()
    }
    /// <p>A list of <a href="https://en.wikipedia.org/wiki/IETF_language_tag">BCP 47</a> compliant language codes for the results to be rendered in. If there is no data for the result in the requested language, data will be returned in the default language for the entry.</p>
    pub fn language(&self) -> ::std::option::Option<&str> {
        self.language.as_deref()
    }
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    /// <p>The following political views are currently supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ARG</code>: Argentina's view on the Southern Patagonian Ice Field and Tierra Del Fuego, including the Falkland Islands, South Georgia, and South Sandwich Islands</p></li>
    /// <li>
    /// <p><code>EGY</code>: Egypt's view on Bir Tawil</p></li>
    /// <li>
    /// <p><code>IND</code>: India's view on Gilgit-Baltistan</p></li>
    /// <li>
    /// <p><code>KEN</code>: Kenya's view on the Ilemi Triangle</p></li>
    /// <li>
    /// <p><code>MAR</code>: Morocco's view on Western Sahara</p></li>
    /// <li>
    /// <p><code>RUS</code>: Russia's view on Crimea</p></li>
    /// <li>
    /// <p><code>SDN</code>: Sudan's view on the Halaib Triangle</p></li>
    /// <li>
    /// <p><code>SRB</code>: Serbia's view on Kosovo, Vukovar, and Sarengrad Islands</p></li>
    /// <li>
    /// <p><code>SUR</code>: Suriname's view on the Courantyne Headwaters and Lawa Headwaters</p></li>
    /// <li>
    /// <p><code>SYR</code>: Syria's view on the Golan Heights</p></li>
    /// <li>
    /// <p><code>TUR</code>: Turkey's view on Cyprus and Northern Cyprus</p></li>
    /// <li>
    /// <p><code>TZA</code>: Tanzania's view on Lake Malawi</p></li>
    /// <li>
    /// <p><code>URY</code>: Uruguay's view on Rincon de Artigas</p></li>
    /// <li>
    /// <p><code>VNM</code>: Vietnam's view on the Paracel Islands and Spratly Islands</p></li>
    /// </ul>
    pub fn political_view(&self) -> ::std::option::Option<&str> {
        self.political_view.as_deref()
    }
    /// <p>Indicates if the results will be stored. Defaults to <code>SingleUse</code>, if left empty.</p>
    pub fn intended_use(&self) -> ::std::option::Option<&crate::types::AutocompleteIntendedUse> {
        self.intended_use.as_ref()
    }
    /// <p>Optional: The API key to be used for authorization. Either an API key or valid SigV4 signature must be provided when making a request.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
}
impl ::std::fmt::Debug for AutocompleteInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AutocompleteInput");
        formatter.field("query_text", &"*** Sensitive Data Redacted ***");
        formatter.field("max_results", &self.max_results);
        formatter.field("bias_position", &"*** Sensitive Data Redacted ***");
        formatter.field("filter", &self.filter);
        formatter.field("postal_code_mode", &self.postal_code_mode);
        formatter.field("additional_features", &self.additional_features);
        formatter.field("language", &self.language);
        formatter.field("political_view", &"*** Sensitive Data Redacted ***");
        formatter.field("intended_use", &self.intended_use);
        formatter.field("key", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl AutocompleteInput {
    /// Creates a new builder-style object to manufacture [`AutocompleteInput`](crate::operation::autocomplete::AutocompleteInput).
    pub fn builder() -> crate::operation::autocomplete::builders::AutocompleteInputBuilder {
        crate::operation::autocomplete::builders::AutocompleteInputBuilder::default()
    }
}

/// A builder for [`AutocompleteInput`](crate::operation::autocomplete::AutocompleteInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AutocompleteInputBuilder {
    pub(crate) query_text: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) bias_position: ::std::option::Option<::std::vec::Vec<f64>>,
    pub(crate) filter: ::std::option::Option<crate::types::AutocompleteFilter>,
    pub(crate) postal_code_mode: ::std::option::Option<crate::types::PostalCodeMode>,
    pub(crate) additional_features: ::std::option::Option<::std::vec::Vec<crate::types::AutocompleteAdditionalFeature>>,
    pub(crate) language: ::std::option::Option<::std::string::String>,
    pub(crate) political_view: ::std::option::Option<::std::string::String>,
    pub(crate) intended_use: ::std::option::Option<crate::types::AutocompleteIntendedUse>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
}
impl AutocompleteInputBuilder {
    /// <p>The free-form text query to match addresses against. This is usually a partially typed address from an end user in an address box or form.</p><note>
    /// <p>The fields <code>QueryText</code>, and <code>QueryID</code> are mutually exclusive.</p>
    /// </note>
    /// This field is required.
    pub fn query_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The free-form text query to match addresses against. This is usually a partially typed address from an end user in an address box or form.</p><note>
    /// <p>The fields <code>QueryText</code>, and <code>QueryID</code> are mutually exclusive.</p>
    /// </note>
    pub fn set_query_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_text = input;
        self
    }
    /// <p>The free-form text query to match addresses against. This is usually a partially typed address from an end user in an address box or form.</p><note>
    /// <p>The fields <code>QueryText</code>, and <code>QueryID</code> are mutually exclusive.</p>
    /// </note>
    pub fn get_query_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_text
    }
    /// <p>An optional limit for the number of results returned in a single call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>An optional limit for the number of results returned in a single call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>An optional limit for the number of results returned in a single call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Appends an item to `bias_position`.
    ///
    /// To override the contents of this collection use [`set_bias_position`](Self::set_bias_position).
    ///
    /// <p>The position in longitude and latitude that the results should be close to. Typically, place results returned are ranked higher the closer they are to this position. Stored in <code>\[lng, lat\]</code> and in the WSG84 format.</p><note>
    /// <p>The fields <code>BiasPosition</code>, <code>FilterBoundingBox</code>, and <code>FilterCircle</code> are mutually exclusive.</p>
    /// </note>
    pub fn bias_position(mut self, input: f64) -> Self {
        let mut v = self.bias_position.unwrap_or_default();
        v.push(input);
        self.bias_position = ::std::option::Option::Some(v);
        self
    }
    /// <p>The position in longitude and latitude that the results should be close to. Typically, place results returned are ranked higher the closer they are to this position. Stored in <code>\[lng, lat\]</code> and in the WSG84 format.</p><note>
    /// <p>The fields <code>BiasPosition</code>, <code>FilterBoundingBox</code>, and <code>FilterCircle</code> are mutually exclusive.</p>
    /// </note>
    pub fn set_bias_position(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.bias_position = input;
        self
    }
    /// <p>The position in longitude and latitude that the results should be close to. Typically, place results returned are ranked higher the closer they are to this position. Stored in <code>\[lng, lat\]</code> and in the WSG84 format.</p><note>
    /// <p>The fields <code>BiasPosition</code>, <code>FilterBoundingBox</code>, and <code>FilterCircle</code> are mutually exclusive.</p>
    /// </note>
    pub fn get_bias_position(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.bias_position
    }
    /// <p>A structure which contains a set of inclusion/exclusion properties that results must possess in order to be returned as a result.</p>
    pub fn filter(mut self, input: crate::types::AutocompleteFilter) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure which contains a set of inclusion/exclusion properties that results must possess in order to be returned as a result.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::AutocompleteFilter>) -> Self {
        self.filter = input;
        self
    }
    /// <p>A structure which contains a set of inclusion/exclusion properties that results must possess in order to be returned as a result.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::AutocompleteFilter> {
        &self.filter
    }
    /// <p>The <code>PostalCodeMode</code> affects how postal code results are returned. If a postal code spans multiple localities and this value is empty, partial district or locality information may be returned under a single postal code result entry. If it's populated with the value <code>EnumerateSpannedLocalities</code>, all cities in that postal code are returned.</p>
    pub fn postal_code_mode(mut self, input: crate::types::PostalCodeMode) -> Self {
        self.postal_code_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>PostalCodeMode</code> affects how postal code results are returned. If a postal code spans multiple localities and this value is empty, partial district or locality information may be returned under a single postal code result entry. If it's populated with the value <code>EnumerateSpannedLocalities</code>, all cities in that postal code are returned.</p>
    pub fn set_postal_code_mode(mut self, input: ::std::option::Option<crate::types::PostalCodeMode>) -> Self {
        self.postal_code_mode = input;
        self
    }
    /// <p>The <code>PostalCodeMode</code> affects how postal code results are returned. If a postal code spans multiple localities and this value is empty, partial district or locality information may be returned under a single postal code result entry. If it's populated with the value <code>EnumerateSpannedLocalities</code>, all cities in that postal code are returned.</p>
    pub fn get_postal_code_mode(&self) -> &::std::option::Option<crate::types::PostalCodeMode> {
        &self.postal_code_mode
    }
    /// Appends an item to `additional_features`.
    ///
    /// To override the contents of this collection use [`set_additional_features`](Self::set_additional_features).
    ///
    /// <p>A list of optional additional parameters that can be requested for each result.</p>
    pub fn additional_features(mut self, input: crate::types::AutocompleteAdditionalFeature) -> Self {
        let mut v = self.additional_features.unwrap_or_default();
        v.push(input);
        self.additional_features = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of optional additional parameters that can be requested for each result.</p>
    pub fn set_additional_features(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AutocompleteAdditionalFeature>>) -> Self {
        self.additional_features = input;
        self
    }
    /// <p>A list of optional additional parameters that can be requested for each result.</p>
    pub fn get_additional_features(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AutocompleteAdditionalFeature>> {
        &self.additional_features
    }
    /// <p>A list of <a href="https://en.wikipedia.org/wiki/IETF_language_tag">BCP 47</a> compliant language codes for the results to be rendered in. If there is no data for the result in the requested language, data will be returned in the default language for the entry.</p>
    pub fn language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A list of <a href="https://en.wikipedia.org/wiki/IETF_language_tag">BCP 47</a> compliant language codes for the results to be rendered in. If there is no data for the result in the requested language, data will be returned in the default language for the entry.</p>
    pub fn set_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.language = input;
        self
    }
    /// <p>A list of <a href="https://en.wikipedia.org/wiki/IETF_language_tag">BCP 47</a> compliant language codes for the results to be rendered in. If there is no data for the result in the requested language, data will be returned in the default language for the entry.</p>
    pub fn get_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.language
    }
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    /// <p>The following political views are currently supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ARG</code>: Argentina's view on the Southern Patagonian Ice Field and Tierra Del Fuego, including the Falkland Islands, South Georgia, and South Sandwich Islands</p></li>
    /// <li>
    /// <p><code>EGY</code>: Egypt's view on Bir Tawil</p></li>
    /// <li>
    /// <p><code>IND</code>: India's view on Gilgit-Baltistan</p></li>
    /// <li>
    /// <p><code>KEN</code>: Kenya's view on the Ilemi Triangle</p></li>
    /// <li>
    /// <p><code>MAR</code>: Morocco's view on Western Sahara</p></li>
    /// <li>
    /// <p><code>RUS</code>: Russia's view on Crimea</p></li>
    /// <li>
    /// <p><code>SDN</code>: Sudan's view on the Halaib Triangle</p></li>
    /// <li>
    /// <p><code>SRB</code>: Serbia's view on Kosovo, Vukovar, and Sarengrad Islands</p></li>
    /// <li>
    /// <p><code>SUR</code>: Suriname's view on the Courantyne Headwaters and Lawa Headwaters</p></li>
    /// <li>
    /// <p><code>SYR</code>: Syria's view on the Golan Heights</p></li>
    /// <li>
    /// <p><code>TUR</code>: Turkey's view on Cyprus and Northern Cyprus</p></li>
    /// <li>
    /// <p><code>TZA</code>: Tanzania's view on Lake Malawi</p></li>
    /// <li>
    /// <p><code>URY</code>: Uruguay's view on Rincon de Artigas</p></li>
    /// <li>
    /// <p><code>VNM</code>: Vietnam's view on the Paracel Islands and Spratly Islands</p></li>
    /// </ul>
    pub fn political_view(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.political_view = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    /// <p>The following political views are currently supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ARG</code>: Argentina's view on the Southern Patagonian Ice Field and Tierra Del Fuego, including the Falkland Islands, South Georgia, and South Sandwich Islands</p></li>
    /// <li>
    /// <p><code>EGY</code>: Egypt's view on Bir Tawil</p></li>
    /// <li>
    /// <p><code>IND</code>: India's view on Gilgit-Baltistan</p></li>
    /// <li>
    /// <p><code>KEN</code>: Kenya's view on the Ilemi Triangle</p></li>
    /// <li>
    /// <p><code>MAR</code>: Morocco's view on Western Sahara</p></li>
    /// <li>
    /// <p><code>RUS</code>: Russia's view on Crimea</p></li>
    /// <li>
    /// <p><code>SDN</code>: Sudan's view on the Halaib Triangle</p></li>
    /// <li>
    /// <p><code>SRB</code>: Serbia's view on Kosovo, Vukovar, and Sarengrad Islands</p></li>
    /// <li>
    /// <p><code>SUR</code>: Suriname's view on the Courantyne Headwaters and Lawa Headwaters</p></li>
    /// <li>
    /// <p><code>SYR</code>: Syria's view on the Golan Heights</p></li>
    /// <li>
    /// <p><code>TUR</code>: Turkey's view on Cyprus and Northern Cyprus</p></li>
    /// <li>
    /// <p><code>TZA</code>: Tanzania's view on Lake Malawi</p></li>
    /// <li>
    /// <p><code>URY</code>: Uruguay's view on Rincon de Artigas</p></li>
    /// <li>
    /// <p><code>VNM</code>: Vietnam's view on the Paracel Islands and Spratly Islands</p></li>
    /// </ul>
    pub fn set_political_view(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.political_view = input;
        self
    }
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    /// <p>The following political views are currently supported:</p>
    /// <ul>
    /// <li>
    /// <p><code>ARG</code>: Argentina's view on the Southern Patagonian Ice Field and Tierra Del Fuego, including the Falkland Islands, South Georgia, and South Sandwich Islands</p></li>
    /// <li>
    /// <p><code>EGY</code>: Egypt's view on Bir Tawil</p></li>
    /// <li>
    /// <p><code>IND</code>: India's view on Gilgit-Baltistan</p></li>
    /// <li>
    /// <p><code>KEN</code>: Kenya's view on the Ilemi Triangle</p></li>
    /// <li>
    /// <p><code>MAR</code>: Morocco's view on Western Sahara</p></li>
    /// <li>
    /// <p><code>RUS</code>: Russia's view on Crimea</p></li>
    /// <li>
    /// <p><code>SDN</code>: Sudan's view on the Halaib Triangle</p></li>
    /// <li>
    /// <p><code>SRB</code>: Serbia's view on Kosovo, Vukovar, and Sarengrad Islands</p></li>
    /// <li>
    /// <p><code>SUR</code>: Suriname's view on the Courantyne Headwaters and Lawa Headwaters</p></li>
    /// <li>
    /// <p><code>SYR</code>: Syria's view on the Golan Heights</p></li>
    /// <li>
    /// <p><code>TUR</code>: Turkey's view on Cyprus and Northern Cyprus</p></li>
    /// <li>
    /// <p><code>TZA</code>: Tanzania's view on Lake Malawi</p></li>
    /// <li>
    /// <p><code>URY</code>: Uruguay's view on Rincon de Artigas</p></li>
    /// <li>
    /// <p><code>VNM</code>: Vietnam's view on the Paracel Islands and Spratly Islands</p></li>
    /// </ul>
    pub fn get_political_view(&self) -> &::std::option::Option<::std::string::String> {
        &self.political_view
    }
    /// <p>Indicates if the results will be stored. Defaults to <code>SingleUse</code>, if left empty.</p>
    pub fn intended_use(mut self, input: crate::types::AutocompleteIntendedUse) -> Self {
        self.intended_use = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if the results will be stored. Defaults to <code>SingleUse</code>, if left empty.</p>
    pub fn set_intended_use(mut self, input: ::std::option::Option<crate::types::AutocompleteIntendedUse>) -> Self {
        self.intended_use = input;
        self
    }
    /// <p>Indicates if the results will be stored. Defaults to <code>SingleUse</code>, if left empty.</p>
    pub fn get_intended_use(&self) -> &::std::option::Option<crate::types::AutocompleteIntendedUse> {
        &self.intended_use
    }
    /// <p>Optional: The API key to be used for authorization. Either an API key or valid SigV4 signature must be provided when making a request.</p>
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Optional: The API key to be used for authorization. Either an API key or valid SigV4 signature must be provided when making a request.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>Optional: The API key to be used for authorization. Either an API key or valid SigV4 signature must be provided when making a request.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// Consumes the builder and constructs a [`AutocompleteInput`](crate::operation::autocomplete::AutocompleteInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::autocomplete::AutocompleteInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::autocomplete::AutocompleteInput {
            query_text: self.query_text,
            max_results: self.max_results,
            bias_position: self.bias_position,
            filter: self.filter,
            postal_code_mode: self.postal_code_mode,
            additional_features: self.additional_features,
            language: self.language,
            political_view: self.political_view,
            intended_use: self.intended_use,
            key: self.key,
        })
    }
}
impl ::std::fmt::Debug for AutocompleteInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AutocompleteInputBuilder");
        formatter.field("query_text", &"*** Sensitive Data Redacted ***");
        formatter.field("max_results", &self.max_results);
        formatter.field("bias_position", &"*** Sensitive Data Redacted ***");
        formatter.field("filter", &self.filter);
        formatter.field("postal_code_mode", &self.postal_code_mode);
        formatter.field("additional_features", &self.additional_features);
        formatter.field("language", &self.language);
        formatter.field("political_view", &"*** Sensitive Data Redacted ***");
        formatter.field("intended_use", &self.intended_use);
        formatter.field("key", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
