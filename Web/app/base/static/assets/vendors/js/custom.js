jQuery(document).ready(function() {
    "use strict";


    /* ------- Preloader ------ */
    jQuery(window).load(function() {
        jQuery(".status").fadeOut();
        jQuery(".preloader").delay(1000).fadeOut("slow");
    });


    /* -------- Appears Menu ------ */
    $(window).on('ready , scroll', function() {
        if ($(window).scrollTop() > 30) {
            $('.blete-main-menu').addClass('minified');
        } else {
            $('.blete-main-menu').removeClass('minified');
        }
    });

    /* ---------- Hide Menu-------- */
    jQuery(".nav a").on("click", function() {
        jQuery("#nav-menu").removeClass("in").addClass("collapse");
    });

    /* --------- One Page Navigation -------- */
    $('#nav-menu').onePageNav({
        currentClass: 'active',
        scrollSpeed: 500,
        easing: 'linear'
    });

    /* ---------- Wow Js ---------- */
    var wow = new WOW({
        boxClass: 'wow', // animated element css class (default is wow)
        animateClass: 'animated', // animation css class (default is animated)
        offset: 250, // distance to the element when triggering the animation (default is 0)
        mobile: true, // trigger animations on mobile devices (default is true)
        live: true, // act on asynchronously loaded content (default is true)
        callback: function(box) {
            // the callback is fired every time an animation is started
            // the argument that is passed in is the DOM node being animated
        }
    });
    wow.init();

    /* ---------- Counter Data---------- */

    $('.blete-counter-section').waypoint(function(direction) {
        $('.blete-counter').countTo({
            speed: 3000
        });
    }, {
        offset: 800,
        triggerOnce: true
    });

    /* -------- Skill Chart -------- */
    $('.blete-skills-wrapper').waypoint(function(direction) {
        $('.chart').easyPieChart({
            barColor: '#90caf9',
            trackColor: '#dadada',
            scaleColor: false,
            easing: 'ease',
            lineCap: 'butt',
            lineWidth: 15,
            size: 200,
            animate: 1000,
            onStep: function(from, to, percent) {
                this.el.children[0].innerHTML = Math.round(percent);
            }
        });
    }, {
        offset: 400
    });

    /* --------- Scroll Up --------- */
    $.scrollUp({
        scrollName: 'scrollUp', // Element ID
        scrollDistance: 300, // Distance from top/bottom before showing element (px)
        scrollFrom: 'top', // 'top' or 'bottom'
        scrollSpeed: 5000, // Speed back to top (ms)
        easingType: 'linear', // Scroll to top easing (see http://easings.net/)
        animation: 'fade', // Fade, slide, none
        animationInSpeed: 200, // Animation in speed (ms)
        animationOutSpeed: 200, // Animation out speed (ms)
        scrollText: 'Scroll to top', // Text for element, can contain HTML
        scrollTitle: false, // Set a custom <a> title if required. Defaults to scrollText
        scrollImg: true, // Set true to use image
        activeOverlay: false, // Set CSS color to display scrollUp active point, e.g '#00FFFF'
        zIndex: 99998, // Z-Index for the overlay
    });

    /* ---------- lightbox ---------- */
    $('.blete-featured-work-img').magnificPopup({
        type: 'image',
        gallery: {
            enabled: true
        }
    });

    $('.flickr-gallery-img').magnificPopup({
        type: 'image',
        gallery: {
            enabled: true
        }
    });


    /* --------- Carousel Slider ---------- */
    // Team Slider
    $("#team-slider").owlCarousel({
        items: 3,
        itemsDesktop: [1199, 2],
        itemsDesktopSmall: [979, 2],
        itemsTablet: [768, 2],
        itemsMobile: [520, 1],
        autoPlay: 4000,
        navigation: false
    });

    // Feature Works
    $("#featured-work-slider").owlCarousel({
        items: 4,
        itemsDesktop: [1199, 3],
        itemsTablet: [860, 2],
        itemsMobile: [480, 1],
        autoPlay: 4000,
        navigation: false
    });

    // Related Works
    $("#related-works-slider").owlCarousel({
        items: 4,
        itemsDesktop: [1199, 3],
        itemsTablet: [860, 2],
        itemsMobile: [480, 1],
        autoPlay: 4000,
        navigation: false
    });

    // Feature Works
    $("#blete-testimonial").owlCarousel({
        items: 1,
        itemsDesktop: [1199, 1],
        itemsDesktopSmall: [979, 1],
        itemsTablet: [768, 1],
        itemsMobile: [520, 1],
        autoPlay: 5000
    });

    // Client Logo
    $("#clients-logo-carousal").owlCarousel({
        items: 5,
        itemsDesktop: [1199, 4],
        itemsDesktopSmall: [979, 4],
        itemsTablet: [768, 3],
        itemsMobile: [520, 1],
        autoPlay: 3500,
        navigation: false,
        pagination: false
    });

    /* ------------ Stellar ----------- */
    $(window).stellar({
        responsive: true,
        positionProperty: 'position'
    });

    /* ---------- ISoptope --------- */
    var $container = $('.blete-portfolio-items');

    // filter items on button click
    $container.isotope({
        filter: '*',
        itemSelector: '.item',
        animationOptions: {
            duration: 750,
            easing: 'linear',
            queue: false
        }
    });


    $('#blete-portfolio-filter ul li a').on('click', function() {
        var selector = $(this).attr('data-filter');
        $container.isotope({
            filter: selector,
            animationOptions: {
                duration: 750,
                easing: 'linear',
                queue: false
            }
        });
        return false;
    });

    var $optionSets = $('#blete-portfolio-filter ul'),
        $optionLinks = $optionSets.find('a');

    $optionLinks.on('click', function() {
        var $this = $(this);
        // don't proceed if already selected
        if ($this.hasClass('selected')) {
            return false;
        }
        var $optionSet = $this.parents('#blete-portfolio-filter ul');
        $optionSet.find('.selected').removeClass('selected');
        $this.addClass('selected');
    });

    /* ------------ Home Slider ------------- */
    $('#blete-slider').sliderPro({
        width: '100%',
        height: 768,
        fade: true,
        arrows: true,
        waitForLayers: true,
        buttons: true,
        autoplay: true,
        autoScaleLayers: false,
        slideAnimationDuration: 1500,
        breakpoints: {
            600: {
                height: 480
            }
        }
    });


});