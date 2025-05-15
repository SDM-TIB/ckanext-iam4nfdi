function calculateEffectiveColor(baseColor, alpha) {
    let baseR = parseInt(baseColor.slice(1, 3), 16),
        baseG = parseInt(baseColor.slice(3, 5), 16),
        baseB = parseInt(baseColor.slice(5, 7), 16);

    let finalR = Math.round(baseR * (1 - alpha) + 255 * alpha),
        finalG = Math.round(baseG * (1 - alpha) + 255 * alpha),
        finalB = Math.round(baseB * (1 - alpha) + 255 * alpha);

    return `rgb(${finalR}, ${finalG}, ${finalB})`;
}

function getAlphaPercentage(element) {
    const style = getComputedStyle(element).backgroundColor,
          rgbaMatch = style.match(/rgba?\((\d+),\s*(\d+),\s*(\d+),?\s*([\d.]+)?\)/);

    if (rgbaMatch && rgbaMatch[4] !== undefined) {
        return parseFloat(rgbaMatch[4]);
    } else {
        return 1.0;
    }
}

function applyEffectiveColor() {
    const base = document.querySelector('.main'),
          wrapper = document.querySelector('.wrapper'),
          or = document.querySelector('.login-register-or-text');

    const baseColor = getComputedStyle(base).backgroundColor,
          hexColor = '#' + baseColor.match(/\d+/g).map(x => parseInt(x).toString(16).padStart(2, '0')).join(''),
          alpha = getAlphaPercentage(wrapper);

    or.style.backgroundColor = calculateEffectiveColor(hexColor, alpha);
}

document.addEventListener('DOMContentLoaded', function (){
   applyEffectiveColor();
});
