module.exports = {
  content: ['./public/templates/*.html', './node_modules/tw-elements/dist/js/**/*.js'],
  theme: {
    screens: {
      sm: '480px',
      md: '768px',
      lg: '976px',
      xl: '1440px'
    },
    extend: {
      backgroundImage:  {
        'cinema': "url('../static/bg.jpg')",
      }
    }
  },
  plugins: [
    require('./node_modules/tw-elements/dist/plugin'),
    require('@tailwindcss/forms'),
  ],
}
