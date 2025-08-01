// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input structure for the JobConfig in an EarthObservationJob.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum JobConfigInput {
    /// <p>An object containing information about the job configuration for BandMath.</p>
    BandMathConfig(crate::types::BandMathConfigInput),
    /// <p>An object containing information about the job configuration for cloud masking.</p>
    CloudMaskingConfig(crate::types::CloudMaskingConfigInput),
    /// <p>An object containing information about the job configuration for cloud removal.</p>
    CloudRemovalConfig(crate::types::CloudRemovalConfigInput),
    /// <p>An object containing information about the job configuration for geomosaic.</p>
    GeoMosaicConfig(crate::types::GeoMosaicConfigInput),
    /// <p>An object containing information about the job configuration for land cover segmentation.</p>
    LandCoverSegmentationConfig(crate::types::LandCoverSegmentationConfigInput),
    /// <p>An object containing information about the job configuration for resampling.</p>
    ResamplingConfig(crate::types::ResamplingConfigInput),
    /// <p>An object containing information about the job configuration for a Stacking Earth Observation job.</p>
    StackConfig(crate::types::StackConfigInput),
    /// <p>An object containing information about the job configuration for temporal statistics.</p>
    TemporalStatisticsConfig(crate::types::TemporalStatisticsConfigInput),
    /// <p>An object containing information about the job configuration for zonal statistics.</p>
    ZonalStatisticsConfig(crate::types::ZonalStatisticsConfigInput),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl JobConfigInput {
    /// Tries to convert the enum instance into [`BandMathConfig`](crate::types::JobConfigInput::BandMathConfig), extracting the inner [`BandMathConfigInput`](crate::types::BandMathConfigInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_band_math_config(&self) -> ::std::result::Result<&crate::types::BandMathConfigInput, &Self> {
        if let JobConfigInput::BandMathConfig(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`BandMathConfig`](crate::types::JobConfigInput::BandMathConfig).
    pub fn is_band_math_config(&self) -> bool {
        self.as_band_math_config().is_ok()
    }
    /// Tries to convert the enum instance into [`CloudMaskingConfig`](crate::types::JobConfigInput::CloudMaskingConfig), extracting the inner [`CloudMaskingConfigInput`](crate::types::CloudMaskingConfigInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_cloud_masking_config(&self) -> ::std::result::Result<&crate::types::CloudMaskingConfigInput, &Self> {
        if let JobConfigInput::CloudMaskingConfig(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CloudMaskingConfig`](crate::types::JobConfigInput::CloudMaskingConfig).
    pub fn is_cloud_masking_config(&self) -> bool {
        self.as_cloud_masking_config().is_ok()
    }
    /// Tries to convert the enum instance into [`CloudRemovalConfig`](crate::types::JobConfigInput::CloudRemovalConfig), extracting the inner [`CloudRemovalConfigInput`](crate::types::CloudRemovalConfigInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_cloud_removal_config(&self) -> ::std::result::Result<&crate::types::CloudRemovalConfigInput, &Self> {
        if let JobConfigInput::CloudRemovalConfig(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CloudRemovalConfig`](crate::types::JobConfigInput::CloudRemovalConfig).
    pub fn is_cloud_removal_config(&self) -> bool {
        self.as_cloud_removal_config().is_ok()
    }
    /// Tries to convert the enum instance into [`GeoMosaicConfig`](crate::types::JobConfigInput::GeoMosaicConfig), extracting the inner [`GeoMosaicConfigInput`](crate::types::GeoMosaicConfigInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_geo_mosaic_config(&self) -> ::std::result::Result<&crate::types::GeoMosaicConfigInput, &Self> {
        if let JobConfigInput::GeoMosaicConfig(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`GeoMosaicConfig`](crate::types::JobConfigInput::GeoMosaicConfig).
    pub fn is_geo_mosaic_config(&self) -> bool {
        self.as_geo_mosaic_config().is_ok()
    }
    /// Tries to convert the enum instance into [`LandCoverSegmentationConfig`](crate::types::JobConfigInput::LandCoverSegmentationConfig), extracting the inner [`LandCoverSegmentationConfigInput`](crate::types::LandCoverSegmentationConfigInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_land_cover_segmentation_config(&self) -> ::std::result::Result<&crate::types::LandCoverSegmentationConfigInput, &Self> {
        if let JobConfigInput::LandCoverSegmentationConfig(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`LandCoverSegmentationConfig`](crate::types::JobConfigInput::LandCoverSegmentationConfig).
    pub fn is_land_cover_segmentation_config(&self) -> bool {
        self.as_land_cover_segmentation_config().is_ok()
    }
    /// Tries to convert the enum instance into [`ResamplingConfig`](crate::types::JobConfigInput::ResamplingConfig), extracting the inner [`ResamplingConfigInput`](crate::types::ResamplingConfigInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_resampling_config(&self) -> ::std::result::Result<&crate::types::ResamplingConfigInput, &Self> {
        if let JobConfigInput::ResamplingConfig(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ResamplingConfig`](crate::types::JobConfigInput::ResamplingConfig).
    pub fn is_resampling_config(&self) -> bool {
        self.as_resampling_config().is_ok()
    }
    /// Tries to convert the enum instance into [`StackConfig`](crate::types::JobConfigInput::StackConfig), extracting the inner [`StackConfigInput`](crate::types::StackConfigInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_stack_config(&self) -> ::std::result::Result<&crate::types::StackConfigInput, &Self> {
        if let JobConfigInput::StackConfig(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`StackConfig`](crate::types::JobConfigInput::StackConfig).
    pub fn is_stack_config(&self) -> bool {
        self.as_stack_config().is_ok()
    }
    /// Tries to convert the enum instance into [`TemporalStatisticsConfig`](crate::types::JobConfigInput::TemporalStatisticsConfig), extracting the inner [`TemporalStatisticsConfigInput`](crate::types::TemporalStatisticsConfigInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_temporal_statistics_config(&self) -> ::std::result::Result<&crate::types::TemporalStatisticsConfigInput, &Self> {
        if let JobConfigInput::TemporalStatisticsConfig(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`TemporalStatisticsConfig`](crate::types::JobConfigInput::TemporalStatisticsConfig).
    pub fn is_temporal_statistics_config(&self) -> bool {
        self.as_temporal_statistics_config().is_ok()
    }
    /// Tries to convert the enum instance into [`ZonalStatisticsConfig`](crate::types::JobConfigInput::ZonalStatisticsConfig), extracting the inner [`ZonalStatisticsConfigInput`](crate::types::ZonalStatisticsConfigInput).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_zonal_statistics_config(&self) -> ::std::result::Result<&crate::types::ZonalStatisticsConfigInput, &Self> {
        if let JobConfigInput::ZonalStatisticsConfig(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ZonalStatisticsConfig`](crate::types::JobConfigInput::ZonalStatisticsConfig).
    pub fn is_zonal_statistics_config(&self) -> bool {
        self.as_zonal_statistics_config().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
