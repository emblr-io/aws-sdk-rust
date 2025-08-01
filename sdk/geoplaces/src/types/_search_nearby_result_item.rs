// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The search results of nearby places.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SearchNearbyResultItem {
    /// <p>The <code>PlaceId</code> of the place you wish to receive the information for.</p>
    pub place_id: ::std::string::String,
    /// <p>A <code>PlaceType</code> is a category that the result place must belong to.</p>
    pub place_type: crate::types::PlaceType,
    /// <p>The item's title.</p>
    pub title: ::std::string::String,
    /// <p>The place's address.</p>
    pub address: ::std::option::Option<crate::types::Address>,
    /// <p>Boolean indicating if the address provided has been corrected.</p>
    pub address_number_corrected: ::std::option::Option<bool>,
    /// <p>The position in longitude and latitude.</p>
    pub position: ::std::option::Option<::std::vec::Vec<f64>>,
    /// <p>The distance in meters from the QueryPosition.</p>
    pub distance: i64,
    /// <p>The bounding box enclosing the geometric shape (area or line) that an individual result covers.</p>
    /// <p>The bounding box formed is defined as a set 4 coordinates: <code>\[{westward lng}, {southern lat}, {eastward lng}, {northern lat}\]</code></p>
    pub map_view: ::std::option::Option<::std::vec::Vec<f64>>,
    /// <p>Categories of results that results must belong to.</p>
    pub categories: ::std::option::Option<::std::vec::Vec<crate::types::Category>>,
    /// <p>List of food types offered by this result.</p>
    pub food_types: ::std::option::Option<::std::vec::Vec<crate::types::FoodType>>,
    /// <p>The Business Chains associated with the place.</p>
    pub business_chains: ::std::option::Option<::std::vec::Vec<crate::types::BusinessChain>>,
    /// <p>List of potential contact methods for the result/place.</p>
    pub contacts: ::std::option::Option<crate::types::Contacts>,
    /// <p>List of opening hours objects.</p>
    pub opening_hours: ::std::option::Option<::std::vec::Vec<crate::types::OpeningHours>>,
    /// <p>Position of the access point represent by longitude and latitude.</p>
    pub access_points: ::std::option::Option<::std::vec::Vec<crate::types::AccessPoint>>,
    /// <p>Indicates known access restrictions on a vehicle access point. The index correlates to an access point and indicates if access through this point has some form of restriction.</p>
    pub access_restrictions: ::std::option::Option<::std::vec::Vec<crate::types::AccessRestriction>>,
    /// <p>The time zone in which the place is located.</p>
    pub time_zone: ::std::option::Option<crate::types::TimeZone>,
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    pub political_view: ::std::option::Option<::std::string::String>,
    /// <p>How the various components of the result's address are pronounced in various languages.</p>
    pub phonemes: ::std::option::Option<crate::types::PhonemeDetails>,
}
impl SearchNearbyResultItem {
    /// <p>The <code>PlaceId</code> of the place you wish to receive the information for.</p>
    pub fn place_id(&self) -> &str {
        use std::ops::Deref;
        self.place_id.deref()
    }
    /// <p>A <code>PlaceType</code> is a category that the result place must belong to.</p>
    pub fn place_type(&self) -> &crate::types::PlaceType {
        &self.place_type
    }
    /// <p>The item's title.</p>
    pub fn title(&self) -> &str {
        use std::ops::Deref;
        self.title.deref()
    }
    /// <p>The place's address.</p>
    pub fn address(&self) -> ::std::option::Option<&crate::types::Address> {
        self.address.as_ref()
    }
    /// <p>Boolean indicating if the address provided has been corrected.</p>
    pub fn address_number_corrected(&self) -> ::std::option::Option<bool> {
        self.address_number_corrected
    }
    /// <p>The position in longitude and latitude.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.position.is_none()`.
    pub fn position(&self) -> &[f64] {
        self.position.as_deref().unwrap_or_default()
    }
    /// <p>The distance in meters from the QueryPosition.</p>
    pub fn distance(&self) -> i64 {
        self.distance
    }
    /// <p>The bounding box enclosing the geometric shape (area or line) that an individual result covers.</p>
    /// <p>The bounding box formed is defined as a set 4 coordinates: <code>\[{westward lng}, {southern lat}, {eastward lng}, {northern lat}\]</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.map_view.is_none()`.
    pub fn map_view(&self) -> &[f64] {
        self.map_view.as_deref().unwrap_or_default()
    }
    /// <p>Categories of results that results must belong to.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.categories.is_none()`.
    pub fn categories(&self) -> &[crate::types::Category] {
        self.categories.as_deref().unwrap_or_default()
    }
    /// <p>List of food types offered by this result.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.food_types.is_none()`.
    pub fn food_types(&self) -> &[crate::types::FoodType] {
        self.food_types.as_deref().unwrap_or_default()
    }
    /// <p>The Business Chains associated with the place.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.business_chains.is_none()`.
    pub fn business_chains(&self) -> &[crate::types::BusinessChain] {
        self.business_chains.as_deref().unwrap_or_default()
    }
    /// <p>List of potential contact methods for the result/place.</p>
    pub fn contacts(&self) -> ::std::option::Option<&crate::types::Contacts> {
        self.contacts.as_ref()
    }
    /// <p>List of opening hours objects.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.opening_hours.is_none()`.
    pub fn opening_hours(&self) -> &[crate::types::OpeningHours] {
        self.opening_hours.as_deref().unwrap_or_default()
    }
    /// <p>Position of the access point represent by longitude and latitude.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.access_points.is_none()`.
    pub fn access_points(&self) -> &[crate::types::AccessPoint] {
        self.access_points.as_deref().unwrap_or_default()
    }
    /// <p>Indicates known access restrictions on a vehicle access point. The index correlates to an access point and indicates if access through this point has some form of restriction.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.access_restrictions.is_none()`.
    pub fn access_restrictions(&self) -> &[crate::types::AccessRestriction] {
        self.access_restrictions.as_deref().unwrap_or_default()
    }
    /// <p>The time zone in which the place is located.</p>
    pub fn time_zone(&self) -> ::std::option::Option<&crate::types::TimeZone> {
        self.time_zone.as_ref()
    }
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    pub fn political_view(&self) -> ::std::option::Option<&str> {
        self.political_view.as_deref()
    }
    /// <p>How the various components of the result's address are pronounced in various languages.</p>
    pub fn phonemes(&self) -> ::std::option::Option<&crate::types::PhonemeDetails> {
        self.phonemes.as_ref()
    }
}
impl ::std::fmt::Debug for SearchNearbyResultItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SearchNearbyResultItem");
        formatter.field("place_id", &"*** Sensitive Data Redacted ***");
        formatter.field("place_type", &"*** Sensitive Data Redacted ***");
        formatter.field("title", &"*** Sensitive Data Redacted ***");
        formatter.field("address", &self.address);
        formatter.field("address_number_corrected", &"*** Sensitive Data Redacted ***");
        formatter.field("position", &"*** Sensitive Data Redacted ***");
        formatter.field("distance", &"*** Sensitive Data Redacted ***");
        formatter.field("map_view", &"*** Sensitive Data Redacted ***");
        formatter.field("categories", &self.categories);
        formatter.field("food_types", &self.food_types);
        formatter.field("business_chains", &self.business_chains);
        formatter.field("contacts", &self.contacts);
        formatter.field("opening_hours", &self.opening_hours);
        formatter.field("access_points", &self.access_points);
        formatter.field("access_restrictions", &self.access_restrictions);
        formatter.field("time_zone", &self.time_zone);
        formatter.field("political_view", &"*** Sensitive Data Redacted ***");
        formatter.field("phonemes", &self.phonemes);
        formatter.finish()
    }
}
impl SearchNearbyResultItem {
    /// Creates a new builder-style object to manufacture [`SearchNearbyResultItem`](crate::types::SearchNearbyResultItem).
    pub fn builder() -> crate::types::builders::SearchNearbyResultItemBuilder {
        crate::types::builders::SearchNearbyResultItemBuilder::default()
    }
}

/// A builder for [`SearchNearbyResultItem`](crate::types::SearchNearbyResultItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SearchNearbyResultItemBuilder {
    pub(crate) place_id: ::std::option::Option<::std::string::String>,
    pub(crate) place_type: ::std::option::Option<crate::types::PlaceType>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) address: ::std::option::Option<crate::types::Address>,
    pub(crate) address_number_corrected: ::std::option::Option<bool>,
    pub(crate) position: ::std::option::Option<::std::vec::Vec<f64>>,
    pub(crate) distance: ::std::option::Option<i64>,
    pub(crate) map_view: ::std::option::Option<::std::vec::Vec<f64>>,
    pub(crate) categories: ::std::option::Option<::std::vec::Vec<crate::types::Category>>,
    pub(crate) food_types: ::std::option::Option<::std::vec::Vec<crate::types::FoodType>>,
    pub(crate) business_chains: ::std::option::Option<::std::vec::Vec<crate::types::BusinessChain>>,
    pub(crate) contacts: ::std::option::Option<crate::types::Contacts>,
    pub(crate) opening_hours: ::std::option::Option<::std::vec::Vec<crate::types::OpeningHours>>,
    pub(crate) access_points: ::std::option::Option<::std::vec::Vec<crate::types::AccessPoint>>,
    pub(crate) access_restrictions: ::std::option::Option<::std::vec::Vec<crate::types::AccessRestriction>>,
    pub(crate) time_zone: ::std::option::Option<crate::types::TimeZone>,
    pub(crate) political_view: ::std::option::Option<::std::string::String>,
    pub(crate) phonemes: ::std::option::Option<crate::types::PhonemeDetails>,
}
impl SearchNearbyResultItemBuilder {
    /// <p>The <code>PlaceId</code> of the place you wish to receive the information for.</p>
    /// This field is required.
    pub fn place_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.place_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>PlaceId</code> of the place you wish to receive the information for.</p>
    pub fn set_place_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.place_id = input;
        self
    }
    /// <p>The <code>PlaceId</code> of the place you wish to receive the information for.</p>
    pub fn get_place_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.place_id
    }
    /// <p>A <code>PlaceType</code> is a category that the result place must belong to.</p>
    /// This field is required.
    pub fn place_type(mut self, input: crate::types::PlaceType) -> Self {
        self.place_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>PlaceType</code> is a category that the result place must belong to.</p>
    pub fn set_place_type(mut self, input: ::std::option::Option<crate::types::PlaceType>) -> Self {
        self.place_type = input;
        self
    }
    /// <p>A <code>PlaceType</code> is a category that the result place must belong to.</p>
    pub fn get_place_type(&self) -> &::std::option::Option<crate::types::PlaceType> {
        &self.place_type
    }
    /// <p>The item's title.</p>
    /// This field is required.
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The item's title.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>The item's title.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>The place's address.</p>
    pub fn address(mut self, input: crate::types::Address) -> Self {
        self.address = ::std::option::Option::Some(input);
        self
    }
    /// <p>The place's address.</p>
    pub fn set_address(mut self, input: ::std::option::Option<crate::types::Address>) -> Self {
        self.address = input;
        self
    }
    /// <p>The place's address.</p>
    pub fn get_address(&self) -> &::std::option::Option<crate::types::Address> {
        &self.address
    }
    /// <p>Boolean indicating if the address provided has been corrected.</p>
    pub fn address_number_corrected(mut self, input: bool) -> Self {
        self.address_number_corrected = ::std::option::Option::Some(input);
        self
    }
    /// <p>Boolean indicating if the address provided has been corrected.</p>
    pub fn set_address_number_corrected(mut self, input: ::std::option::Option<bool>) -> Self {
        self.address_number_corrected = input;
        self
    }
    /// <p>Boolean indicating if the address provided has been corrected.</p>
    pub fn get_address_number_corrected(&self) -> &::std::option::Option<bool> {
        &self.address_number_corrected
    }
    /// Appends an item to `position`.
    ///
    /// To override the contents of this collection use [`set_position`](Self::set_position).
    ///
    /// <p>The position in longitude and latitude.</p>
    pub fn position(mut self, input: f64) -> Self {
        let mut v = self.position.unwrap_or_default();
        v.push(input);
        self.position = ::std::option::Option::Some(v);
        self
    }
    /// <p>The position in longitude and latitude.</p>
    pub fn set_position(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.position = input;
        self
    }
    /// <p>The position in longitude and latitude.</p>
    pub fn get_position(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.position
    }
    /// <p>The distance in meters from the QueryPosition.</p>
    pub fn distance(mut self, input: i64) -> Self {
        self.distance = ::std::option::Option::Some(input);
        self
    }
    /// <p>The distance in meters from the QueryPosition.</p>
    pub fn set_distance(mut self, input: ::std::option::Option<i64>) -> Self {
        self.distance = input;
        self
    }
    /// <p>The distance in meters from the QueryPosition.</p>
    pub fn get_distance(&self) -> &::std::option::Option<i64> {
        &self.distance
    }
    /// Appends an item to `map_view`.
    ///
    /// To override the contents of this collection use [`set_map_view`](Self::set_map_view).
    ///
    /// <p>The bounding box enclosing the geometric shape (area or line) that an individual result covers.</p>
    /// <p>The bounding box formed is defined as a set 4 coordinates: <code>\[{westward lng}, {southern lat}, {eastward lng}, {northern lat}\]</code></p>
    pub fn map_view(mut self, input: f64) -> Self {
        let mut v = self.map_view.unwrap_or_default();
        v.push(input);
        self.map_view = ::std::option::Option::Some(v);
        self
    }
    /// <p>The bounding box enclosing the geometric shape (area or line) that an individual result covers.</p>
    /// <p>The bounding box formed is defined as a set 4 coordinates: <code>\[{westward lng}, {southern lat}, {eastward lng}, {northern lat}\]</code></p>
    pub fn set_map_view(mut self, input: ::std::option::Option<::std::vec::Vec<f64>>) -> Self {
        self.map_view = input;
        self
    }
    /// <p>The bounding box enclosing the geometric shape (area or line) that an individual result covers.</p>
    /// <p>The bounding box formed is defined as a set 4 coordinates: <code>\[{westward lng}, {southern lat}, {eastward lng}, {northern lat}\]</code></p>
    pub fn get_map_view(&self) -> &::std::option::Option<::std::vec::Vec<f64>> {
        &self.map_view
    }
    /// Appends an item to `categories`.
    ///
    /// To override the contents of this collection use [`set_categories`](Self::set_categories).
    ///
    /// <p>Categories of results that results must belong to.</p>
    pub fn categories(mut self, input: crate::types::Category) -> Self {
        let mut v = self.categories.unwrap_or_default();
        v.push(input);
        self.categories = ::std::option::Option::Some(v);
        self
    }
    /// <p>Categories of results that results must belong to.</p>
    pub fn set_categories(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Category>>) -> Self {
        self.categories = input;
        self
    }
    /// <p>Categories of results that results must belong to.</p>
    pub fn get_categories(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Category>> {
        &self.categories
    }
    /// Appends an item to `food_types`.
    ///
    /// To override the contents of this collection use [`set_food_types`](Self::set_food_types).
    ///
    /// <p>List of food types offered by this result.</p>
    pub fn food_types(mut self, input: crate::types::FoodType) -> Self {
        let mut v = self.food_types.unwrap_or_default();
        v.push(input);
        self.food_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of food types offered by this result.</p>
    pub fn set_food_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FoodType>>) -> Self {
        self.food_types = input;
        self
    }
    /// <p>List of food types offered by this result.</p>
    pub fn get_food_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FoodType>> {
        &self.food_types
    }
    /// Appends an item to `business_chains`.
    ///
    /// To override the contents of this collection use [`set_business_chains`](Self::set_business_chains).
    ///
    /// <p>The Business Chains associated with the place.</p>
    pub fn business_chains(mut self, input: crate::types::BusinessChain) -> Self {
        let mut v = self.business_chains.unwrap_or_default();
        v.push(input);
        self.business_chains = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Business Chains associated with the place.</p>
    pub fn set_business_chains(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BusinessChain>>) -> Self {
        self.business_chains = input;
        self
    }
    /// <p>The Business Chains associated with the place.</p>
    pub fn get_business_chains(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BusinessChain>> {
        &self.business_chains
    }
    /// <p>List of potential contact methods for the result/place.</p>
    pub fn contacts(mut self, input: crate::types::Contacts) -> Self {
        self.contacts = ::std::option::Option::Some(input);
        self
    }
    /// <p>List of potential contact methods for the result/place.</p>
    pub fn set_contacts(mut self, input: ::std::option::Option<crate::types::Contacts>) -> Self {
        self.contacts = input;
        self
    }
    /// <p>List of potential contact methods for the result/place.</p>
    pub fn get_contacts(&self) -> &::std::option::Option<crate::types::Contacts> {
        &self.contacts
    }
    /// Appends an item to `opening_hours`.
    ///
    /// To override the contents of this collection use [`set_opening_hours`](Self::set_opening_hours).
    ///
    /// <p>List of opening hours objects.</p>
    pub fn opening_hours(mut self, input: crate::types::OpeningHours) -> Self {
        let mut v = self.opening_hours.unwrap_or_default();
        v.push(input);
        self.opening_hours = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of opening hours objects.</p>
    pub fn set_opening_hours(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OpeningHours>>) -> Self {
        self.opening_hours = input;
        self
    }
    /// <p>List of opening hours objects.</p>
    pub fn get_opening_hours(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OpeningHours>> {
        &self.opening_hours
    }
    /// Appends an item to `access_points`.
    ///
    /// To override the contents of this collection use [`set_access_points`](Self::set_access_points).
    ///
    /// <p>Position of the access point represent by longitude and latitude.</p>
    pub fn access_points(mut self, input: crate::types::AccessPoint) -> Self {
        let mut v = self.access_points.unwrap_or_default();
        v.push(input);
        self.access_points = ::std::option::Option::Some(v);
        self
    }
    /// <p>Position of the access point represent by longitude and latitude.</p>
    pub fn set_access_points(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AccessPoint>>) -> Self {
        self.access_points = input;
        self
    }
    /// <p>Position of the access point represent by longitude and latitude.</p>
    pub fn get_access_points(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AccessPoint>> {
        &self.access_points
    }
    /// Appends an item to `access_restrictions`.
    ///
    /// To override the contents of this collection use [`set_access_restrictions`](Self::set_access_restrictions).
    ///
    /// <p>Indicates known access restrictions on a vehicle access point. The index correlates to an access point and indicates if access through this point has some form of restriction.</p>
    pub fn access_restrictions(mut self, input: crate::types::AccessRestriction) -> Self {
        let mut v = self.access_restrictions.unwrap_or_default();
        v.push(input);
        self.access_restrictions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates known access restrictions on a vehicle access point. The index correlates to an access point and indicates if access through this point has some form of restriction.</p>
    pub fn set_access_restrictions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AccessRestriction>>) -> Self {
        self.access_restrictions = input;
        self
    }
    /// <p>Indicates known access restrictions on a vehicle access point. The index correlates to an access point and indicates if access through this point has some form of restriction.</p>
    pub fn get_access_restrictions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AccessRestriction>> {
        &self.access_restrictions
    }
    /// <p>The time zone in which the place is located.</p>
    pub fn time_zone(mut self, input: crate::types::TimeZone) -> Self {
        self.time_zone = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time zone in which the place is located.</p>
    pub fn set_time_zone(mut self, input: ::std::option::Option<crate::types::TimeZone>) -> Self {
        self.time_zone = input;
        self
    }
    /// <p>The time zone in which the place is located.</p>
    pub fn get_time_zone(&self) -> &::std::option::Option<crate::types::TimeZone> {
        &self.time_zone
    }
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    pub fn political_view(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.political_view = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    pub fn set_political_view(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.political_view = input;
        self
    }
    /// <p>The alpha-2 or alpha-3 character code for the political view of a country. The political view applies to the results of the request to represent unresolved territorial claims through the point of view of the specified country.</p>
    pub fn get_political_view(&self) -> &::std::option::Option<::std::string::String> {
        &self.political_view
    }
    /// <p>How the various components of the result's address are pronounced in various languages.</p>
    pub fn phonemes(mut self, input: crate::types::PhonemeDetails) -> Self {
        self.phonemes = ::std::option::Option::Some(input);
        self
    }
    /// <p>How the various components of the result's address are pronounced in various languages.</p>
    pub fn set_phonemes(mut self, input: ::std::option::Option<crate::types::PhonemeDetails>) -> Self {
        self.phonemes = input;
        self
    }
    /// <p>How the various components of the result's address are pronounced in various languages.</p>
    pub fn get_phonemes(&self) -> &::std::option::Option<crate::types::PhonemeDetails> {
        &self.phonemes
    }
    /// Consumes the builder and constructs a [`SearchNearbyResultItem`](crate::types::SearchNearbyResultItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`place_id`](crate::types::builders::SearchNearbyResultItemBuilder::place_id)
    /// - [`place_type`](crate::types::builders::SearchNearbyResultItemBuilder::place_type)
    /// - [`title`](crate::types::builders::SearchNearbyResultItemBuilder::title)
    pub fn build(self) -> ::std::result::Result<crate::types::SearchNearbyResultItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SearchNearbyResultItem {
            place_id: self.place_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "place_id",
                    "place_id was not specified but it is required when building SearchNearbyResultItem",
                )
            })?,
            place_type: self.place_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "place_type",
                    "place_type was not specified but it is required when building SearchNearbyResultItem",
                )
            })?,
            title: self.title.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "title",
                    "title was not specified but it is required when building SearchNearbyResultItem",
                )
            })?,
            address: self.address,
            address_number_corrected: self.address_number_corrected,
            position: self.position,
            distance: self.distance.unwrap_or_default(),
            map_view: self.map_view,
            categories: self.categories,
            food_types: self.food_types,
            business_chains: self.business_chains,
            contacts: self.contacts,
            opening_hours: self.opening_hours,
            access_points: self.access_points,
            access_restrictions: self.access_restrictions,
            time_zone: self.time_zone,
            political_view: self.political_view,
            phonemes: self.phonemes,
        })
    }
}
impl ::std::fmt::Debug for SearchNearbyResultItemBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SearchNearbyResultItemBuilder");
        formatter.field("place_id", &"*** Sensitive Data Redacted ***");
        formatter.field("place_type", &"*** Sensitive Data Redacted ***");
        formatter.field("title", &"*** Sensitive Data Redacted ***");
        formatter.field("address", &self.address);
        formatter.field("address_number_corrected", &"*** Sensitive Data Redacted ***");
        formatter.field("position", &"*** Sensitive Data Redacted ***");
        formatter.field("distance", &"*** Sensitive Data Redacted ***");
        formatter.field("map_view", &"*** Sensitive Data Redacted ***");
        formatter.field("categories", &self.categories);
        formatter.field("food_types", &self.food_types);
        formatter.field("business_chains", &self.business_chains);
        formatter.field("contacts", &self.contacts);
        formatter.field("opening_hours", &self.opening_hours);
        formatter.field("access_points", &self.access_points);
        formatter.field("access_restrictions", &self.access_restrictions);
        formatter.field("time_zone", &self.time_zone);
        formatter.field("political_view", &"*** Sensitive Data Redacted ***");
        formatter.field("phonemes", &self.phonemes);
        formatter.finish()
    }
}
