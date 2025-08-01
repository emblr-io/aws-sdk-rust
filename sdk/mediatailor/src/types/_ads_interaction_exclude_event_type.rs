// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `AdsInteractionExcludeEventType`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let adsinteractionexcludeeventtype = unimplemented!();
/// match adsinteractionexcludeeventtype {
///     AdsInteractionExcludeEventType::AdMarkerFound => { /* ... */ },
///     AdsInteractionExcludeEventType::BeaconFired => { /* ... */ },
///     AdsInteractionExcludeEventType::EmptyVastResponse => { /* ... */ },
///     AdsInteractionExcludeEventType::EmptyVmapResponse => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorAdsInvalidResponse => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorAdsIo => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorAdsResponseParse => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorAdsResponseUnknownRootElement => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorAdsTimeout => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorDisallowedHost => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorFiringBeaconFailed => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorPersonalizationDisabled => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorUnknown => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorUnknownHost => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastInvalidMediaFile => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastInvalidVastAdTagUri => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastMissingCreatives => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastMissingImpression => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastMissingMediafiles => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastMissingOverlays => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastMultipleLinear => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastMultipleTrackingEvents => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastRedirectEmptyResponse => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastRedirectFailed => { /* ... */ },
///     AdsInteractionExcludeEventType::ErrorVastRedirectMultipleVast => { /* ... */ },
///     AdsInteractionExcludeEventType::FilledAvail => { /* ... */ },
///     AdsInteractionExcludeEventType::FilledOverlayAvail => { /* ... */ },
///     AdsInteractionExcludeEventType::InterstitialVodFailure => { /* ... */ },
///     AdsInteractionExcludeEventType::InterstitialVodSuccess => { /* ... */ },
///     AdsInteractionExcludeEventType::MakingAdsRequest => { /* ... */ },
///     AdsInteractionExcludeEventType::ModifiedTargetUrl => { /* ... */ },
///     AdsInteractionExcludeEventType::NonAdMarkerFound => { /* ... */ },
///     AdsInteractionExcludeEventType::RedirectedVastResponse => { /* ... */ },
///     AdsInteractionExcludeEventType::VastRedirect => { /* ... */ },
///     AdsInteractionExcludeEventType::VastResponse => { /* ... */ },
///     AdsInteractionExcludeEventType::VodTimeBasedAvailPlanSuccess => { /* ... */ },
///     AdsInteractionExcludeEventType::VodTimeBasedAvailPlanVastResponseForOffset => { /* ... */ },
///     AdsInteractionExcludeEventType::VodTimeBasedAvailPlanWarningNoAdvertisements => { /* ... */ },
///     AdsInteractionExcludeEventType::WarningNoAdvertisements => { /* ... */ },
///     AdsInteractionExcludeEventType::WarningUrlVariableSubstitutionFailed => { /* ... */ },
///     AdsInteractionExcludeEventType::WarningVpaidAdDropped => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `adsinteractionexcludeeventtype` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `AdsInteractionExcludeEventType::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `AdsInteractionExcludeEventType::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `AdsInteractionExcludeEventType::NewFeature` is defined.
/// Specifically, when `adsinteractionexcludeeventtype` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `AdsInteractionExcludeEventType::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum AdsInteractionExcludeEventType {
    #[allow(missing_docs)] // documentation missing in model
    AdMarkerFound,
    #[allow(missing_docs)] // documentation missing in model
    BeaconFired,
    #[allow(missing_docs)] // documentation missing in model
    EmptyVastResponse,
    #[allow(missing_docs)] // documentation missing in model
    EmptyVmapResponse,
    #[allow(missing_docs)] // documentation missing in model
    ErrorAdsInvalidResponse,
    #[allow(missing_docs)] // documentation missing in model
    ErrorAdsIo,
    #[allow(missing_docs)] // documentation missing in model
    ErrorAdsResponseParse,
    #[allow(missing_docs)] // documentation missing in model
    ErrorAdsResponseUnknownRootElement,
    #[allow(missing_docs)] // documentation missing in model
    ErrorAdsTimeout,
    #[allow(missing_docs)] // documentation missing in model
    ErrorDisallowedHost,
    #[allow(missing_docs)] // documentation missing in model
    ErrorFiringBeaconFailed,
    #[allow(missing_docs)] // documentation missing in model
    ErrorPersonalizationDisabled,
    #[allow(missing_docs)] // documentation missing in model
    ErrorUnknown,
    #[allow(missing_docs)] // documentation missing in model
    ErrorUnknownHost,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastInvalidMediaFile,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastInvalidVastAdTagUri,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastMissingCreatives,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastMissingImpression,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastMissingMediafiles,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastMissingOverlays,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastMultipleLinear,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastMultipleTrackingEvents,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastRedirectEmptyResponse,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastRedirectFailed,
    #[allow(missing_docs)] // documentation missing in model
    ErrorVastRedirectMultipleVast,
    #[allow(missing_docs)] // documentation missing in model
    FilledAvail,
    #[allow(missing_docs)] // documentation missing in model
    FilledOverlayAvail,
    #[allow(missing_docs)] // documentation missing in model
    InterstitialVodFailure,
    #[allow(missing_docs)] // documentation missing in model
    InterstitialVodSuccess,
    #[allow(missing_docs)] // documentation missing in model
    MakingAdsRequest,
    #[allow(missing_docs)] // documentation missing in model
    ModifiedTargetUrl,
    #[allow(missing_docs)] // documentation missing in model
    NonAdMarkerFound,
    #[allow(missing_docs)] // documentation missing in model
    RedirectedVastResponse,
    #[allow(missing_docs)] // documentation missing in model
    VastRedirect,
    #[allow(missing_docs)] // documentation missing in model
    VastResponse,
    #[allow(missing_docs)] // documentation missing in model
    VodTimeBasedAvailPlanSuccess,
    #[allow(missing_docs)] // documentation missing in model
    VodTimeBasedAvailPlanVastResponseForOffset,
    #[allow(missing_docs)] // documentation missing in model
    VodTimeBasedAvailPlanWarningNoAdvertisements,
    #[allow(missing_docs)] // documentation missing in model
    WarningNoAdvertisements,
    #[allow(missing_docs)] // documentation missing in model
    WarningUrlVariableSubstitutionFailed,
    #[allow(missing_docs)] // documentation missing in model
    WarningVpaidAdDropped,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for AdsInteractionExcludeEventType {
    fn from(s: &str) -> Self {
        match s {
            "AD_MARKER_FOUND" => AdsInteractionExcludeEventType::AdMarkerFound,
            "BEACON_FIRED" => AdsInteractionExcludeEventType::BeaconFired,
            "EMPTY_VAST_RESPONSE" => AdsInteractionExcludeEventType::EmptyVastResponse,
            "EMPTY_VMAP_RESPONSE" => AdsInteractionExcludeEventType::EmptyVmapResponse,
            "ERROR_ADS_INVALID_RESPONSE" => AdsInteractionExcludeEventType::ErrorAdsInvalidResponse,
            "ERROR_ADS_IO" => AdsInteractionExcludeEventType::ErrorAdsIo,
            "ERROR_ADS_RESPONSE_PARSE" => AdsInteractionExcludeEventType::ErrorAdsResponseParse,
            "ERROR_ADS_RESPONSE_UNKNOWN_ROOT_ELEMENT" => AdsInteractionExcludeEventType::ErrorAdsResponseUnknownRootElement,
            "ERROR_ADS_TIMEOUT" => AdsInteractionExcludeEventType::ErrorAdsTimeout,
            "ERROR_DISALLOWED_HOST" => AdsInteractionExcludeEventType::ErrorDisallowedHost,
            "ERROR_FIRING_BEACON_FAILED" => AdsInteractionExcludeEventType::ErrorFiringBeaconFailed,
            "ERROR_PERSONALIZATION_DISABLED" => AdsInteractionExcludeEventType::ErrorPersonalizationDisabled,
            "ERROR_UNKNOWN" => AdsInteractionExcludeEventType::ErrorUnknown,
            "ERROR_UNKNOWN_HOST" => AdsInteractionExcludeEventType::ErrorUnknownHost,
            "ERROR_VAST_INVALID_MEDIA_FILE" => AdsInteractionExcludeEventType::ErrorVastInvalidMediaFile,
            "ERROR_VAST_INVALID_VAST_AD_TAG_URI" => AdsInteractionExcludeEventType::ErrorVastInvalidVastAdTagUri,
            "ERROR_VAST_MISSING_CREATIVES" => AdsInteractionExcludeEventType::ErrorVastMissingCreatives,
            "ERROR_VAST_MISSING_IMPRESSION" => AdsInteractionExcludeEventType::ErrorVastMissingImpression,
            "ERROR_VAST_MISSING_MEDIAFILES" => AdsInteractionExcludeEventType::ErrorVastMissingMediafiles,
            "ERROR_VAST_MISSING_OVERLAYS" => AdsInteractionExcludeEventType::ErrorVastMissingOverlays,
            "ERROR_VAST_MULTIPLE_LINEAR" => AdsInteractionExcludeEventType::ErrorVastMultipleLinear,
            "ERROR_VAST_MULTIPLE_TRACKING_EVENTS" => AdsInteractionExcludeEventType::ErrorVastMultipleTrackingEvents,
            "ERROR_VAST_REDIRECT_EMPTY_RESPONSE" => AdsInteractionExcludeEventType::ErrorVastRedirectEmptyResponse,
            "ERROR_VAST_REDIRECT_FAILED" => AdsInteractionExcludeEventType::ErrorVastRedirectFailed,
            "ERROR_VAST_REDIRECT_MULTIPLE_VAST" => AdsInteractionExcludeEventType::ErrorVastRedirectMultipleVast,
            "FILLED_AVAIL" => AdsInteractionExcludeEventType::FilledAvail,
            "FILLED_OVERLAY_AVAIL" => AdsInteractionExcludeEventType::FilledOverlayAvail,
            "INTERSTITIAL_VOD_FAILURE" => AdsInteractionExcludeEventType::InterstitialVodFailure,
            "INTERSTITIAL_VOD_SUCCESS" => AdsInteractionExcludeEventType::InterstitialVodSuccess,
            "MAKING_ADS_REQUEST" => AdsInteractionExcludeEventType::MakingAdsRequest,
            "MODIFIED_TARGET_URL" => AdsInteractionExcludeEventType::ModifiedTargetUrl,
            "NON_AD_MARKER_FOUND" => AdsInteractionExcludeEventType::NonAdMarkerFound,
            "REDIRECTED_VAST_RESPONSE" => AdsInteractionExcludeEventType::RedirectedVastResponse,
            "VAST_REDIRECT" => AdsInteractionExcludeEventType::VastRedirect,
            "VAST_RESPONSE" => AdsInteractionExcludeEventType::VastResponse,
            "VOD_TIME_BASED_AVAIL_PLAN_SUCCESS" => AdsInteractionExcludeEventType::VodTimeBasedAvailPlanSuccess,
            "VOD_TIME_BASED_AVAIL_PLAN_VAST_RESPONSE_FOR_OFFSET" => AdsInteractionExcludeEventType::VodTimeBasedAvailPlanVastResponseForOffset,
            "VOD_TIME_BASED_AVAIL_PLAN_WARNING_NO_ADVERTISEMENTS" => AdsInteractionExcludeEventType::VodTimeBasedAvailPlanWarningNoAdvertisements,
            "WARNING_NO_ADVERTISEMENTS" => AdsInteractionExcludeEventType::WarningNoAdvertisements,
            "WARNING_URL_VARIABLE_SUBSTITUTION_FAILED" => AdsInteractionExcludeEventType::WarningUrlVariableSubstitutionFailed,
            "WARNING_VPAID_AD_DROPPED" => AdsInteractionExcludeEventType::WarningVpaidAdDropped,
            other => AdsInteractionExcludeEventType::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for AdsInteractionExcludeEventType {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(AdsInteractionExcludeEventType::from(s))
    }
}
impl AdsInteractionExcludeEventType {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            AdsInteractionExcludeEventType::AdMarkerFound => "AD_MARKER_FOUND",
            AdsInteractionExcludeEventType::BeaconFired => "BEACON_FIRED",
            AdsInteractionExcludeEventType::EmptyVastResponse => "EMPTY_VAST_RESPONSE",
            AdsInteractionExcludeEventType::EmptyVmapResponse => "EMPTY_VMAP_RESPONSE",
            AdsInteractionExcludeEventType::ErrorAdsInvalidResponse => "ERROR_ADS_INVALID_RESPONSE",
            AdsInteractionExcludeEventType::ErrorAdsIo => "ERROR_ADS_IO",
            AdsInteractionExcludeEventType::ErrorAdsResponseParse => "ERROR_ADS_RESPONSE_PARSE",
            AdsInteractionExcludeEventType::ErrorAdsResponseUnknownRootElement => "ERROR_ADS_RESPONSE_UNKNOWN_ROOT_ELEMENT",
            AdsInteractionExcludeEventType::ErrorAdsTimeout => "ERROR_ADS_TIMEOUT",
            AdsInteractionExcludeEventType::ErrorDisallowedHost => "ERROR_DISALLOWED_HOST",
            AdsInteractionExcludeEventType::ErrorFiringBeaconFailed => "ERROR_FIRING_BEACON_FAILED",
            AdsInteractionExcludeEventType::ErrorPersonalizationDisabled => "ERROR_PERSONALIZATION_DISABLED",
            AdsInteractionExcludeEventType::ErrorUnknown => "ERROR_UNKNOWN",
            AdsInteractionExcludeEventType::ErrorUnknownHost => "ERROR_UNKNOWN_HOST",
            AdsInteractionExcludeEventType::ErrorVastInvalidMediaFile => "ERROR_VAST_INVALID_MEDIA_FILE",
            AdsInteractionExcludeEventType::ErrorVastInvalidVastAdTagUri => "ERROR_VAST_INVALID_VAST_AD_TAG_URI",
            AdsInteractionExcludeEventType::ErrorVastMissingCreatives => "ERROR_VAST_MISSING_CREATIVES",
            AdsInteractionExcludeEventType::ErrorVastMissingImpression => "ERROR_VAST_MISSING_IMPRESSION",
            AdsInteractionExcludeEventType::ErrorVastMissingMediafiles => "ERROR_VAST_MISSING_MEDIAFILES",
            AdsInteractionExcludeEventType::ErrorVastMissingOverlays => "ERROR_VAST_MISSING_OVERLAYS",
            AdsInteractionExcludeEventType::ErrorVastMultipleLinear => "ERROR_VAST_MULTIPLE_LINEAR",
            AdsInteractionExcludeEventType::ErrorVastMultipleTrackingEvents => "ERROR_VAST_MULTIPLE_TRACKING_EVENTS",
            AdsInteractionExcludeEventType::ErrorVastRedirectEmptyResponse => "ERROR_VAST_REDIRECT_EMPTY_RESPONSE",
            AdsInteractionExcludeEventType::ErrorVastRedirectFailed => "ERROR_VAST_REDIRECT_FAILED",
            AdsInteractionExcludeEventType::ErrorVastRedirectMultipleVast => "ERROR_VAST_REDIRECT_MULTIPLE_VAST",
            AdsInteractionExcludeEventType::FilledAvail => "FILLED_AVAIL",
            AdsInteractionExcludeEventType::FilledOverlayAvail => "FILLED_OVERLAY_AVAIL",
            AdsInteractionExcludeEventType::InterstitialVodFailure => "INTERSTITIAL_VOD_FAILURE",
            AdsInteractionExcludeEventType::InterstitialVodSuccess => "INTERSTITIAL_VOD_SUCCESS",
            AdsInteractionExcludeEventType::MakingAdsRequest => "MAKING_ADS_REQUEST",
            AdsInteractionExcludeEventType::ModifiedTargetUrl => "MODIFIED_TARGET_URL",
            AdsInteractionExcludeEventType::NonAdMarkerFound => "NON_AD_MARKER_FOUND",
            AdsInteractionExcludeEventType::RedirectedVastResponse => "REDIRECTED_VAST_RESPONSE",
            AdsInteractionExcludeEventType::VastRedirect => "VAST_REDIRECT",
            AdsInteractionExcludeEventType::VastResponse => "VAST_RESPONSE",
            AdsInteractionExcludeEventType::VodTimeBasedAvailPlanSuccess => "VOD_TIME_BASED_AVAIL_PLAN_SUCCESS",
            AdsInteractionExcludeEventType::VodTimeBasedAvailPlanVastResponseForOffset => "VOD_TIME_BASED_AVAIL_PLAN_VAST_RESPONSE_FOR_OFFSET",
            AdsInteractionExcludeEventType::VodTimeBasedAvailPlanWarningNoAdvertisements => "VOD_TIME_BASED_AVAIL_PLAN_WARNING_NO_ADVERTISEMENTS",
            AdsInteractionExcludeEventType::WarningNoAdvertisements => "WARNING_NO_ADVERTISEMENTS",
            AdsInteractionExcludeEventType::WarningUrlVariableSubstitutionFailed => "WARNING_URL_VARIABLE_SUBSTITUTION_FAILED",
            AdsInteractionExcludeEventType::WarningVpaidAdDropped => "WARNING_VPAID_AD_DROPPED",
            AdsInteractionExcludeEventType::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "AD_MARKER_FOUND",
            "BEACON_FIRED",
            "EMPTY_VAST_RESPONSE",
            "EMPTY_VMAP_RESPONSE",
            "ERROR_ADS_INVALID_RESPONSE",
            "ERROR_ADS_IO",
            "ERROR_ADS_RESPONSE_PARSE",
            "ERROR_ADS_RESPONSE_UNKNOWN_ROOT_ELEMENT",
            "ERROR_ADS_TIMEOUT",
            "ERROR_DISALLOWED_HOST",
            "ERROR_FIRING_BEACON_FAILED",
            "ERROR_PERSONALIZATION_DISABLED",
            "ERROR_UNKNOWN",
            "ERROR_UNKNOWN_HOST",
            "ERROR_VAST_INVALID_MEDIA_FILE",
            "ERROR_VAST_INVALID_VAST_AD_TAG_URI",
            "ERROR_VAST_MISSING_CREATIVES",
            "ERROR_VAST_MISSING_IMPRESSION",
            "ERROR_VAST_MISSING_MEDIAFILES",
            "ERROR_VAST_MISSING_OVERLAYS",
            "ERROR_VAST_MULTIPLE_LINEAR",
            "ERROR_VAST_MULTIPLE_TRACKING_EVENTS",
            "ERROR_VAST_REDIRECT_EMPTY_RESPONSE",
            "ERROR_VAST_REDIRECT_FAILED",
            "ERROR_VAST_REDIRECT_MULTIPLE_VAST",
            "FILLED_AVAIL",
            "FILLED_OVERLAY_AVAIL",
            "INTERSTITIAL_VOD_FAILURE",
            "INTERSTITIAL_VOD_SUCCESS",
            "MAKING_ADS_REQUEST",
            "MODIFIED_TARGET_URL",
            "NON_AD_MARKER_FOUND",
            "REDIRECTED_VAST_RESPONSE",
            "VAST_REDIRECT",
            "VAST_RESPONSE",
            "VOD_TIME_BASED_AVAIL_PLAN_SUCCESS",
            "VOD_TIME_BASED_AVAIL_PLAN_VAST_RESPONSE_FOR_OFFSET",
            "VOD_TIME_BASED_AVAIL_PLAN_WARNING_NO_ADVERTISEMENTS",
            "WARNING_NO_ADVERTISEMENTS",
            "WARNING_URL_VARIABLE_SUBSTITUTION_FAILED",
            "WARNING_VPAID_AD_DROPPED",
        ]
    }
}
impl ::std::convert::AsRef<str> for AdsInteractionExcludeEventType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl AdsInteractionExcludeEventType {
    /// Parses the enum value while disallowing unknown variants.
    ///
    /// Unknown variants will result in an error.
    pub fn try_parse(value: &str) -> ::std::result::Result<Self, crate::error::UnknownVariantError> {
        match Self::from(value) {
            #[allow(deprecated)]
            Self::Unknown(_) => ::std::result::Result::Err(crate::error::UnknownVariantError::new(value)),
            known => Ok(known),
        }
    }
}
impl ::std::fmt::Display for AdsInteractionExcludeEventType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            AdsInteractionExcludeEventType::AdMarkerFound => write!(f, "AD_MARKER_FOUND"),
            AdsInteractionExcludeEventType::BeaconFired => write!(f, "BEACON_FIRED"),
            AdsInteractionExcludeEventType::EmptyVastResponse => write!(f, "EMPTY_VAST_RESPONSE"),
            AdsInteractionExcludeEventType::EmptyVmapResponse => write!(f, "EMPTY_VMAP_RESPONSE"),
            AdsInteractionExcludeEventType::ErrorAdsInvalidResponse => write!(f, "ERROR_ADS_INVALID_RESPONSE"),
            AdsInteractionExcludeEventType::ErrorAdsIo => write!(f, "ERROR_ADS_IO"),
            AdsInteractionExcludeEventType::ErrorAdsResponseParse => write!(f, "ERROR_ADS_RESPONSE_PARSE"),
            AdsInteractionExcludeEventType::ErrorAdsResponseUnknownRootElement => write!(f, "ERROR_ADS_RESPONSE_UNKNOWN_ROOT_ELEMENT"),
            AdsInteractionExcludeEventType::ErrorAdsTimeout => write!(f, "ERROR_ADS_TIMEOUT"),
            AdsInteractionExcludeEventType::ErrorDisallowedHost => write!(f, "ERROR_DISALLOWED_HOST"),
            AdsInteractionExcludeEventType::ErrorFiringBeaconFailed => write!(f, "ERROR_FIRING_BEACON_FAILED"),
            AdsInteractionExcludeEventType::ErrorPersonalizationDisabled => write!(f, "ERROR_PERSONALIZATION_DISABLED"),
            AdsInteractionExcludeEventType::ErrorUnknown => write!(f, "ERROR_UNKNOWN"),
            AdsInteractionExcludeEventType::ErrorUnknownHost => write!(f, "ERROR_UNKNOWN_HOST"),
            AdsInteractionExcludeEventType::ErrorVastInvalidMediaFile => write!(f, "ERROR_VAST_INVALID_MEDIA_FILE"),
            AdsInteractionExcludeEventType::ErrorVastInvalidVastAdTagUri => write!(f, "ERROR_VAST_INVALID_VAST_AD_TAG_URI"),
            AdsInteractionExcludeEventType::ErrorVastMissingCreatives => write!(f, "ERROR_VAST_MISSING_CREATIVES"),
            AdsInteractionExcludeEventType::ErrorVastMissingImpression => write!(f, "ERROR_VAST_MISSING_IMPRESSION"),
            AdsInteractionExcludeEventType::ErrorVastMissingMediafiles => write!(f, "ERROR_VAST_MISSING_MEDIAFILES"),
            AdsInteractionExcludeEventType::ErrorVastMissingOverlays => write!(f, "ERROR_VAST_MISSING_OVERLAYS"),
            AdsInteractionExcludeEventType::ErrorVastMultipleLinear => write!(f, "ERROR_VAST_MULTIPLE_LINEAR"),
            AdsInteractionExcludeEventType::ErrorVastMultipleTrackingEvents => write!(f, "ERROR_VAST_MULTIPLE_TRACKING_EVENTS"),
            AdsInteractionExcludeEventType::ErrorVastRedirectEmptyResponse => write!(f, "ERROR_VAST_REDIRECT_EMPTY_RESPONSE"),
            AdsInteractionExcludeEventType::ErrorVastRedirectFailed => write!(f, "ERROR_VAST_REDIRECT_FAILED"),
            AdsInteractionExcludeEventType::ErrorVastRedirectMultipleVast => write!(f, "ERROR_VAST_REDIRECT_MULTIPLE_VAST"),
            AdsInteractionExcludeEventType::FilledAvail => write!(f, "FILLED_AVAIL"),
            AdsInteractionExcludeEventType::FilledOverlayAvail => write!(f, "FILLED_OVERLAY_AVAIL"),
            AdsInteractionExcludeEventType::InterstitialVodFailure => write!(f, "INTERSTITIAL_VOD_FAILURE"),
            AdsInteractionExcludeEventType::InterstitialVodSuccess => write!(f, "INTERSTITIAL_VOD_SUCCESS"),
            AdsInteractionExcludeEventType::MakingAdsRequest => write!(f, "MAKING_ADS_REQUEST"),
            AdsInteractionExcludeEventType::ModifiedTargetUrl => write!(f, "MODIFIED_TARGET_URL"),
            AdsInteractionExcludeEventType::NonAdMarkerFound => write!(f, "NON_AD_MARKER_FOUND"),
            AdsInteractionExcludeEventType::RedirectedVastResponse => write!(f, "REDIRECTED_VAST_RESPONSE"),
            AdsInteractionExcludeEventType::VastRedirect => write!(f, "VAST_REDIRECT"),
            AdsInteractionExcludeEventType::VastResponse => write!(f, "VAST_RESPONSE"),
            AdsInteractionExcludeEventType::VodTimeBasedAvailPlanSuccess => write!(f, "VOD_TIME_BASED_AVAIL_PLAN_SUCCESS"),
            AdsInteractionExcludeEventType::VodTimeBasedAvailPlanVastResponseForOffset => {
                write!(f, "VOD_TIME_BASED_AVAIL_PLAN_VAST_RESPONSE_FOR_OFFSET")
            }
            AdsInteractionExcludeEventType::VodTimeBasedAvailPlanWarningNoAdvertisements => {
                write!(f, "VOD_TIME_BASED_AVAIL_PLAN_WARNING_NO_ADVERTISEMENTS")
            }
            AdsInteractionExcludeEventType::WarningNoAdvertisements => write!(f, "WARNING_NO_ADVERTISEMENTS"),
            AdsInteractionExcludeEventType::WarningUrlVariableSubstitutionFailed => write!(f, "WARNING_URL_VARIABLE_SUBSTITUTION_FAILED"),
            AdsInteractionExcludeEventType::WarningVpaidAdDropped => write!(f, "WARNING_VPAID_AD_DROPPED"),
            AdsInteractionExcludeEventType::Unknown(value) => write!(f, "{}", value),
        }
    }
}
